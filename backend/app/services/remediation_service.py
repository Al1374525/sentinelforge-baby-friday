"""
Remediation Service - Execute Kubernetes Actions
Handles actual remediation actions based on RL decisions
"""
from datetime import datetime
from kubernetes import client, config
from app.models.threat_event import ThreatEvent
from app.models.remediation_action import RemediationAction
from app.storage import actions_db
import logging

logger = logging.getLogger(__name__)


class RemediationService:
    """Service for executing remediation actions"""
    
    def __init__(self):
        self.k8s_client = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize Kubernetes client"""
        try:
            config.load_kube_config()
            self.k8s_client = client.CoreV1Api()
            self.initialized = True
            print("✅ Remediation Service initialized (Kubernetes client)")
        except Exception as e:
            print(f"⚠️  Kubernetes client not available: {e}")
            print("   Running in simulated mode")
            self.initialized = False
    
    async def execute_action(self, action: RemediationAction, threat: ThreatEvent):
        """
        Execute remediation action
        Based on Decision 4B: Moderate - auto-execute low-risk, confirm high-risk
        """
        action.executed_at = datetime.utcnow()
        
        try:
            if action.requires_confirmation:
                # High-risk actions require confirmation (Decision 4B)
                logger.warning(f"⚠️  Action {action.action_type.value} requires confirmation (risk: {action.risk_level.value})")
                action.executed = False
                action.success = None
                return
            
            # Execute based on action type
            if action.action_type.value == "terminate_pod":
                success = await self._terminate_pod(threat.source_pod, threat.source_namespace or "default")
            elif action.action_type.value == "isolate_pod":
                success = await self._isolate_pod(threat.source_pod, threat.source_namespace or "default")
            elif action.action_type.value == "alert":
                success = await self._send_alert(threat)
            elif action.action_type.value == "log":
                success = await self._log_event(threat)
            else:
                success = True  # Monitor action always succeeds
            
            action.executed = True
            action.success = success
            
            # Store action
            actions_db.append(action)
            
            if success:
                print(f"✅ Action executed: {action.action_type.value} for threat {threat.id}")
            else:
                print(f"❌ Action failed: {action.action_type.value} for threat {threat.id}")
        
        except Exception as e:
            logger.error(f"Error executing action: {e}")
            action.executed = True
            action.success = False
            action.error_message = str(e)
    
    async def _terminate_pod(self, pod_name: str, namespace: str) -> bool:
        """Terminate a pod"""
        if not self.initialized or not self.k8s_client:
            print(f"   [SIMULATED] Would terminate pod {pod_name} in namespace {namespace}")
            return True
        
        try:
            self.k8s_client.delete_namespaced_pod(
                name=pod_name,
                namespace=namespace,
                grace_period_seconds=0
            )
            return True
        except Exception as e:
            logger.error(f"Failed to terminate pod {pod_name}: {e}")
            return False
    
    async def _isolate_pod(self, pod_name: str, namespace: str) -> bool:
        """Isolate pod using network policy"""
        if not self.initialized or not self.k8s_client:
            print(f"   [SIMULATED] Would isolate pod {pod_name} in namespace {namespace}")
            return True
        
        try:
            # Create network policy to isolate pod
            # This is a simplified version - in production, would create proper NetworkPolicy
            from kubernetes.client import V1NetworkPolicy, V1NetworkPolicySpec, V1NetworkPolicyIngressRule
            
            network_policy = V1NetworkPolicy(
                metadata=client.V1ObjectMeta(
                    name=f"{pod_name}-isolate",
                    namespace=namespace
                ),
                spec=V1NetworkPolicySpec(
                    pod_selector={"matchLabels": {"pod-name": pod_name}},
                    policy_types=["Ingress", "Egress"],
                    ingress=[],  # No ingress allowed
                    egress=[]    # No egress allowed
                )
            )
            
            networking_api = client.NetworkingV1Api()
            networking_api.create_namespaced_network_policy(
                namespace=namespace,
                body=network_policy
            )
            return True
        except Exception as e:
            logger.error(f"Failed to isolate pod {pod_name}: {e}")
            return False
    
    async def _send_alert(self, threat: ThreatEvent) -> bool:
        """Send alert (for now, just log)"""
        print(f"🚨 ALERT: {threat.severity.value.upper()} threat detected: {threat.description[:100]}")
        return True
    
    async def _log_event(self, threat: ThreatEvent) -> bool:
        """Log event"""
        logger.info(f"Threat logged: {threat.threat_type.value} in {threat.source_pod}")
        return True
    
    async def health_check(self) -> dict:
        """Health check for remediation service"""
        return {
            "status": "healthy" if self.initialized else "degraded",
            "k8s_available": self.k8s_client is not None
        }
