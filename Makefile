.PHONY: up demo attack clean

up:
kind create cluster --config kind-config.yaml --name babyfriday || true
kubectl apply -f https://raw.githubusercontent.com/falcosecurity/charts/master/falco/falco.yaml
timeout /t 25 /nobreak >nul
docker compose up -d brain

demo:
@echo Baby FRIDAY is protecting the cluster. Run 'make attack' to see her in action!

attack:
kubectl apply -f attacker/evil-pod.yaml

clean:
kind delete cluster --name babyfriday
docker compose down
