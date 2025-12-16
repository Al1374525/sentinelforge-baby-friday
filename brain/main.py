from fastapi import FastAPI, Request
from kubernetes import client, config

try:
    config.load_kube_config()
    v1 = client.CoreV1Api()
except:
    v1 = None  # fallback if kube config issue

app = FastAPI(title="SentinelForge – Baby FRIDAY")

async def process_event(event):
    output = event.get("output", "")
    if any(keyword in output.lower() for keyword in ["reverse shell", "nc", "shell"]):
        pod = event.get("k8s", {}).get("pod", {}).get("name", "unknown")
        explanation = f"Sir, pod {pod} attempted a reverse shell. I have terminated the container to secure the system."  # Hardcoded FRIDAY response
        print("\nFRIDAY:", explanation)
        if v1:
            try:
                v1.delete_namespaced_pod(pod, "default", grace_period_seconds=0)
                print("   → Pod terminated.\n")
            except Exception as e:
                print(f"   → Could not terminate pod: {e}\n")
        else:
            print("   → Kubernetes client not available (simulated mode)\n")

@app.post("/simulate")
async def simulate(request: Request):
    try:
        event = await request.json()
        print("Simulated threat received")
        await process_event(event)
        return {"status": "processed"}
    except Exception as e:
        print(f"Error: {e}")
        return {"error": str(e)}

@app.get("/")
async def root():
    return {"message": "Baby FRIDAY is online"}