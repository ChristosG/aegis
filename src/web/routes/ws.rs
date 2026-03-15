use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use tracing::{debug, warn};

use crate::web::server::AppContext;

pub async fn ws_threats(ws: WebSocketUpgrade, State(ctx): State<AppContext>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, ctx))
}

async fn handle_ws(mut socket: WebSocket, ctx: AppContext) {
    let mut rx = ctx.event_bus.subscribe();

    debug!("WebSocket client connected");

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(threat) => {
                        let json = serde_json::to_string(&threat).unwrap_or_default();
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(missed = n, "WebSocket client lagged, skipped events");
                    }
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    debug!("WebSocket client disconnected");
}
