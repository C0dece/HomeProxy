use std::{
    io::{self, Write},
    path::Path,
};

pub fn load(path: &Path) -> io::Result<Vec<u8>> {
    transform(&std::fs::read(path)?, false)
}

pub fn save(path: &Path, data: &[u8]) -> io::Result<()> {
    let protected = transform(data, true)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("state directory unavailable"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&protected)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}

#[cfg(windows)]
fn transform(data: &[u8], protect: bool) -> io::Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: data
            .len()
            .try_into()
            .map_err(|_| io::Error::other("state too large"))?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    // DPAPI binds the ciphertext to the current Windows account.
    unsafe {
        let status = if protect {
            CryptProtectData(
                &input,
                null(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                null(),
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if status == 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData.cast());
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn transform(_: &[u8], _: bool) -> io::Result<Vec<u8>> {
    Err(io::Error::other(
        "protected client storage is implemented for Windows",
    ))
}
