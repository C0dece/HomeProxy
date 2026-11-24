use homeproxy_agent::android_policy::render;
use jni::{
    objects::{JByteArray, JClass, JString},
    sys::{jboolean, jstring},
    JNIEnv,
};
use serde_json::{json, Value};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

struct Android<R: Runtime>(PluginHandle<R>);

pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("homeproxy-mobile")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.homeproxy.agent", "HomeProxyPlugin")?;
            app.manage(Android(handle));
            Ok(())
        })
        .build()
}

#[no_mangle]
pub extern "system" fn Java_app_homeproxy_agent_AndroidUpdates_verify(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    spki: JByteArray<'_>,
    payload: JByteArray<'_>,
    signature: JByteArray<'_>,
) -> jboolean {
    let (Ok(spki), Ok(payload), Ok(signature)) = (
        env.convert_byte_array(spki),
        env.convert_byte_array(payload),
        env.convert_byte_array(signature),
    ) else {
        return 0;
    };
    let prefix = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let Some(key) = spki.strip_prefix(&prefix).filter(|key| key.len() == 32) else {
        return 0;
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&payload, &signature)
        .is_ok()
        .into()
}

#[tauri::command]
pub async fn agent_command<R: Runtime>(
    app: tauri::AppHandle<R>,
    command: String,
    data: Value,
) -> Result<Value, String> {
    let payload = json!({"command": command, "dataJson": data.to_string()});
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<Android<R>>()
            .0
            .run_mobile_plugin("execute", payload)
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|_| "Команда прервана")?
}

#[tauri::command]
pub async fn start_agent<R: Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    agent_command(app, "enable".into(), json!({"enabled": true}))
        .await
        .map(|_| ())
}

#[no_mangle]
pub extern "system" fn Java_app_homeproxy_agent_NativePlan_render(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    payload: JString<'_>,
) -> jstring {
    let raw = env.get_string(&payload).map(|s| String::from(s));
    let result = match raw {
        Ok(raw) => render(&raw).unwrap_or_else(|error| json!({"error": error})),
        Err(_) => json!({"error": "Конфигурация VPN недоступна"}),
    };
    env.new_string(result.to_string())
        .map(|value| value.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
