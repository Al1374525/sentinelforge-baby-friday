from fastapi import FastAPI, WebSocket
import json, asyncio, ollama
from kubernetes import client, config
config.load_kube_config()
v1 = client.CoreV1Api()

app = FastAPI(title="SentinelForge  Baby FRIDAY")

@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    print("FRIDAY online. Waiting for threats")
    while True:
        try:
            data = await asyncio.wait_for(websocket.receive_text(), timeout=5)
            event = json.loads(data)
            output = event.get("output", "")
            if "reverse shell" in output.lower() or "nc" in output.lower():
                pod = event.get("k8s", {}).get("pod", {}).get("name", "unknown")
                explanation = ollama.generate(
                    model="llama3.2:3b",
                    prompt=f"You are FRIDAY from Iron Man. In one calm, confident sentence explain this alert and the action you took: Pod {pod} attempted a reverse shell."
                )["response"]
                print("\nFRIDAY:", explanation)
                try:
                    v1.delete_namespaced_pod(pod, "default", grace_period_seconds=0)
                    print("    Pod terminated.\n")
                except:
                    print("    Could not terminate pod.\n")
        except:
            continue
