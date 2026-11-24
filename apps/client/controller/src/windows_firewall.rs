use std::{
    ffi::{OsStr, OsString},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    ptr::null_mut,
};

use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            CloseHandle, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND,
            HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
        },
        NetworkManagement::{
            IpHelper::ConvertInterfaceAliasToLuid, Ndis::NET_LUID_LH, WindowsFilteringPlatform::*,
        },
        System::{
            Rpc::RPC_C_AUTHN_WINNT,
            SystemInformation::GetSystemDirectoryW,
            Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
        },
    },
};

const SUBLAYER: GUID = GUID::from_u128(0xf1828703_3e18_4d7c_8d57_0a502faff901);
const LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];
const BLOCK_KEYS: [GUID; 2] = [
    GUID::from_u128(0xf1828703_3e18_4d7c_8d57_0a502faff902),
    GUID::from_u128(0xf1828703_3e18_4d7c_8d57_0a502faff903),
];
const LOCAL_KEYS: [GUID; 2] = [
    GUID::from_u128(0xf1828703_3e18_4d7c_8d57_0a502faff904),
    GUID::from_u128(0xf1828703_3e18_4d7c_8d57_0a502faff905),
];

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn check(code: u32, operation: &str) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("WFP {operation}: 0x{code:08X}"))
    }
}

struct Lock(HANDLE);
impl Lock {
    fn take() -> Result<Self, String> {
        let name = wide("Global\\HomeProxyWindowsStrict");
        unsafe {
            let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
            if handle.is_null() {
                return Err("Не удалось открыть блокировку HomeProxy STRICT".into());
            }
            if !matches!(
                WaitForSingleObject(handle, 0),
                WAIT_OBJECT_0 | WAIT_ABANDONED
            ) {
                CloseHandle(handle);
                return Err("Другой HomeProxy STRICT уже работает".into());
            }
            Ok(Self(handle))
        }
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

pub(crate) struct Session(HANDLE);
impl Session {
    fn open(dynamic: bool) -> Result<Self, String> {
        let options = FWPM_SESSION0 {
            flags: if dynamic {
                FWPM_SESSION_FLAG_DYNAMIC
            } else {
                0
            },
            txnWaitTimeoutInMSec: 3000,
            ..Default::default()
        };
        let mut handle = null_mut();
        check(
            unsafe {
                FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null(),
                    &options,
                    &mut handle,
                )
            },
            "open",
        )?;
        Ok(Self(handle))
    }

    fn transaction(&self, body: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "begin transaction",
        )?;
        let result =
            body().and_then(|()| check(unsafe { FwpmTransactionCommit0(self.0) }, "commit"));
        if result.is_err() {
            unsafe {
                FwpmTransactionAbort0(self.0);
            }
        }
        result
    }

    fn filter(
        &self,
        layer: GUID,
        key: Option<GUID>,
        permit: bool,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> Result<(), String> {
        let mut name = wide(if permit {
            "HomeProxy STRICT permit"
        } else {
            "HomeProxy STRICT block"
        });
        let persistent = if key.is_some() {
            FWPM_FILTER_FLAG_PERSISTENT
        } else {
            0
        };
        let filter = FWPM_FILTER0 {
            filterKey: key.unwrap_or_default(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: persistent
                | if permit {
                    0
                } else {
                    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
                },
            layerKey: layer,
            subLayerKey: SUBLAYER,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: if permit { 15 } else { 0 },
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: if permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let code = unsafe { FwpmFilterAdd0(self.0, &filter, null_mut(), null_mut()) };
        if key.is_some() && code == FWP_E_ALREADY_EXISTS as u32 {
            return Ok(());
        }
        check(code, "add filter")
    }

    pub(crate) fn permit_interface(alias: &str) -> Result<Self, String> {
        let name = wide(alias);
        let mut luid = NET_LUID_LH::default();
        check(
            unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) },
            "locate TUN interface",
        )?;
        let mut id = unsafe { luid.Value };
        let session = Self::open(true)?;
        session.transaction(|| {
            for layer in LAYERS {
                let mut condition = [condition(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 { uint64: &mut id },
                )];
                session.filter(layer, None, true, &mut condition)?;
            }
            Ok(())
        })?;
        Ok(session)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

fn condition(
    field: GUID,
    kind: FWP_DATA_TYPE,
    data: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: data,
        },
    }
}

pub(crate) struct StrictGuard {
    _permits: Session,
    _lock: Lock,
}
impl StrictGuard {
    pub(crate) fn arm(agent: &Path, core: &Path) -> Result<Self, String> {
        let paths = [agent, core].map(|path| {
            std::fs::canonicalize(path)
                .map_err(|_| "Не удалось определить полный путь приложения для WFP")
        });
        let [agent, core] = paths;
        let paths = [agent?, core?];
        let lock = Lock::take()?;
        let persistent = Session::open(false)?;
        persistent.transaction(|| {
            let mut name = wide("HomeProxy STRICT");
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: SUBLAYER,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: null_mut(),
                },
                flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                weight: 0xff00,
                ..Default::default()
            };
            let code = unsafe { FwpmSubLayerAdd0(persistent.0, &sublayer, null_mut()) };
            if code != FWP_E_ALREADY_EXISTS as u32 {
                check(code, "add sublayer")?;
            }
            for (index, layer) in LAYERS.into_iter().enumerate() {
                let mut loopback = condition(
                    FWPM_CONDITION_FLAGS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                );
                loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
                persistent.filter(layer, Some(LOCAL_KEYS[index]), true, &mut [loopback])?;
                persistent.filter(layer, Some(BLOCK_KEYS[index]), false, &mut [])?;
            }
            Ok(())
        })?;
        let permits = Session::open(true)?;
        permits.transaction(|| {
            for path in &paths {
                // WFP uses the Win32 file name. Remove the extended-length DOS
                // prefix returned by canonicalize, keeping the expanded spelling.
                let path = path.as_os_str().encode_wide().collect::<Vec<_>>();
                let extended_dos: Vec<_> = r"\\?\".encode_utf16().collect();
                let extended_unc: Vec<_> = r"\\?\UNC\".encode_utf16().collect();
                let mut filename = Vec::new();
                let tail = if let Some(tail) = path.strip_prefix(extended_unc.as_slice()) {
                    filename.extend(r"\\".encode_utf16());
                    tail
                } else {
                    path.strip_prefix(extended_dos.as_slice()).unwrap_or(&path)
                };
                filename.extend_from_slice(tail);
                filename.push(0);
                let mut blob = null_mut();
                check(
                    unsafe { FwpmGetAppIdFromFileName0(filename.as_ptr(), &mut blob) },
                    "resolve permitted application",
                )?;
                let result = LAYERS.into_iter().try_for_each(|layer| {
                    let app = condition(
                        FWPM_CONDITION_ALE_APP_ID,
                        FWP_BYTE_BLOB_TYPE,
                        FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                    );
                    permits.filter(layer, None, true, &mut [app])
                });
                unsafe {
                    FwpmFreeMemory0((&mut blob as *mut *mut FWP_BYTE_BLOB).cast());
                }
                result?;
            }
            Ok(())
        })?;
        Ok(Self {
            _permits: permits,
            _lock: lock,
        })
    }
}

pub fn reset() -> Result<(), String> {
    crate::windows_tun::check_elevation()?;
    let _lock = Lock::take()?;
    let session = Session::open(false)?;
    session.transaction(|| {
        for key in BLOCK_KEYS.into_iter().chain(LOCAL_KEYS) {
            let code = unsafe { FwpmFilterDeleteByKey0(session.0, &key) };
            if code != FWP_E_FILTER_NOT_FOUND as u32 {
                check(code, "remove filter")?;
            }
        }
        let code = unsafe { FwpmSubLayerDeleteByKey0(session.0, &SUBLAYER) };
        if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {
            Ok(())
        } else {
            check(code, "remove sublayer")
        }
    })?;

    // Windows can still hold FakeIP responses after the TUN has been stopped.
    let mut system = [0; 261];
    let length = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if length == 0 || length >= system.len() {
        return Err("Фильтры сняты, но каталог Windows для сброса DNS недоступен".into());
    }
    let ipconfig = PathBuf::from(OsString::from_wide(&system[..length])).join("ipconfig.exe");
    if Command::new(ipconfig)
        .arg("/flushdns")
        .creation_flags(0x08000000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        Ok(())
    } else {
        Err("Фильтры сняты, но кеш DNS Windows не очищен".into())
    }
}
