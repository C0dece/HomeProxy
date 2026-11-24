use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{Name as DnsName, RData, RecordType},
};
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    header::{ACCEPT, CONTENT_TYPE},
    Client,
};

use crate::windows_tun::{DOH_ADDRESSES, DOH_NAME};

const DNS_MEDIA_TYPE: &str = "application/dns-message";
const DOH_URL: &str = "https://dns.quad9.net/dns-query";

type DnsError = Box<dyn Error + Send + Sync>;

pub(crate) struct BootstrapDns(Client);

impl BootstrapDns {
    pub(crate) fn new() -> Result<Self, reqwest::Error> {
        let addresses =
            DOH_ADDRESSES.map(|ip| SocketAddr::new(ip.parse().expect("static DoH IP"), 443));
        Client::builder()
            .no_proxy()
            .https_only(true)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .resolve_to_addrs(DOH_NAME, &addresses)
            .build()
            .map(Self)
    }
}

async fn query(
    client: &Client,
    name: DnsName,
    kind: RecordType,
) -> Result<Vec<SocketAddr>, DnsError> {
    let question = Query::query(name, kind);
    let mut request = Message::new();
    request
        .set_id(0)
        .set_recursion_desired(true)
        .add_query(question.clone());
    let mut response = client
        .post(DOH_URL)
        .header(ACCEPT, DNS_MEDIA_TYPE)
        .header(CONTENT_TYPE, DNS_MEDIA_TYPE)
        .body(request.to_vec()?)
        .send()
        .await?
        .error_for_status()?;
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some(DNS_MEDIA_TYPE)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid DoH content type").into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > u16::MAX as usize {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "Oversized DoH response").into(),
            );
        }
        body.extend_from_slice(&chunk);
    }
    decode_answer(&body, &question)
}

fn decode_answer(data: &[u8], question: &Query) -> Result<Vec<SocketAddr>, DnsError> {
    let response = Message::from_vec(data)?;
    if response.message_type() != MessageType::Response
        || response.id() != 0
        || response.truncated()
        || response.response_code() != ResponseCode::NoError
        || response.queries() != std::slice::from_ref(question)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unexpected DoH response").into());
    }

    let mut name = question.name();
    for _ in 0..=response.answers().len() {
        let records = || {
            response
                .answers()
                .iter()
                .filter(|record| record.name() == name)
        };
        let addresses: Vec<_> = records()
            .filter_map(|record| match (question.query_type(), record.data()) {
                (RecordType::A, RData::A(ip)) => Some(SocketAddr::new(IpAddr::V4(ip.0), 0)),
                (RecordType::AAAA, RData::AAAA(ip)) => Some(SocketAddr::new(IpAddr::V6(ip.0), 0)),
                _ => None,
            })
            .collect();
        if !addresses.is_empty() {
            return Ok(addresses);
        }
        match records().find_map(|record| match record.data() {
            RData::CNAME(alias) => Some(&alias.0),
            _ => None,
        }) {
            Some(alias) => name = alias,
            None => return Ok(addresses),
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "Cyclic DoH answer").into())
}

impl Resolve for BootstrapDns {
    fn resolve(&self, name: Name) -> Resolving {
        let client = self.0.clone();
        Box::pin(async move {
            if name
                .as_str()
                .trim_end_matches('.')
                .eq_ignore_ascii_case("localhost")
            {
                return Ok(Box::new(
                    [
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        IpAddr::V6(Ipv6Addr::LOCALHOST),
                    ]
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, 0)),
                ) as Addrs);
            }
            let mut dns_name = DnsName::from_ascii(name.as_str())?;
            dns_name.set_fqdn(true);
            let (ipv4, ipv6) = futures_util::future::join(
                query(&client, dns_name.clone(), RecordType::A),
                query(&client, dns_name, RecordType::AAAA),
            )
            .await;
            if std::env::var_os("HOMEPROXY_DIAGNOSTIC_CORE_STDERR").is_some() {
                for error in [&ipv4, &ipv6]
                    .into_iter()
                    .filter_map(|result| result.as_ref().err())
                {
                    eprintln!("STRICT DoH: {error:?}");
                }
            }
            let addresses: Vec<_> = ipv4.into_iter().chain(ipv6).flatten().collect();
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No address from bootstrap DoH",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{
        rdata::{A, CNAME},
        Record,
    };

    #[test]
    fn answers_follow_only_the_requested_name_and_its_alias() {
        let host = DnsName::from_ascii("management.homeproxy.test.").unwrap();
        let alias = DnsName::from_ascii("edge.homeproxy.test.").unwrap();
        let question = Query::query(host.clone(), RecordType::A);
        let mut response = Message::new();
        response
            .set_message_type(MessageType::Response)
            .add_query(question.clone())
            .add_answer(Record::from_rdata(
                host,
                60,
                RData::CNAME(CNAME(alias.clone())),
            ))
            .add_answer(Record::from_rdata(
                alias,
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 25))),
            ))
            .add_answer(Record::from_rdata(
                DnsName::from_ascii("unrelated.homeproxy.test.").unwrap(),
                60,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 26))),
            ));
        assert_eq!(
            decode_answer(&response.to_vec().unwrap(), &question).unwrap(),
            ["192.0.2.25:0".parse::<SocketAddr>().unwrap()]
        );
        response.set_id(1);
        assert!(decode_answer(&response.to_vec().unwrap(), &question).is_err());
    }
}
