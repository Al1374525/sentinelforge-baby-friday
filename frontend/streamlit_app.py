"""
SentinelForge - Streamlit UI
MVP Dashboard for threat visualization
"""
import streamlit as st
import requests
import json
from datetime import datetime
import time

# Page config
st.set_page_config(
    page_title="SentinelForge",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# API endpoint
API_BASE = st.sidebar.text_input("API Base URL", value="http://localhost:8000")

# Custom CSS for FRIDAY-inspired design
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #00FFFF;
        text-align: center;
        text-shadow: 0 0 10px #00FFFF;
        margin-bottom: 2rem;
    }
    .threat-card {
        border: 2px solid #00FFFF;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
        background: rgba(0, 255, 255, 0.1);
    }
    .severity-critical {
        color: #FF0000;
        font-weight: bold;
    }
    .severity-high {
        color: #FF6600;
        font-weight: bold;
    }
    .severity-medium {
        color: #FFAA00;
    }
    .severity-low {
        color: #00AAFF;
    }
</style>
""", unsafe_allow_html=True)

def fetch_threats():
    """Fetch threats from API"""
    try:
        response = requests.get(f"{API_BASE}/api/v1/threats?limit=50")
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.error(f"Error fetching threats: {e}")
        return []

def fetch_actions():
    """Fetch actions from API"""
    try:
        response = requests.get(f"{API_BASE}/api/v1/actions?limit=50")
        if response.status_code == 200:
            return response.json()
        return []
    except Exception as e:
        st.error(f"Error fetching actions: {e}")
        return []

def get_severity_color(severity):
    """Get color for severity"""
    colors = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFAA00",
        "low": "#00AAFF"
    }
    return colors.get(severity.lower(), "#FFFFFF")

# Header
st.markdown('<div class="main-header">🛡️ SENTINELFORGE</div>', unsafe_allow_html=True)
st.markdown('<p style="text-align: center; color: #00FFFF; font-size: 1.2rem;">Autonomous Cybersecurity Platform</p>', unsafe_allow_html=True)

# Sidebar
st.sidebar.title("Navigation")
page = st.sidebar.radio("Select Page", ["Threats Dashboard", "Actions Log", "System Health"])

# Health check
try:
    health_response = requests.get(f"{API_BASE}/health", timeout=2)
    if health_response.status_code == 200:
        health_data = health_response.json()
        st.sidebar.success("✅ Backend Online")
        st.sidebar.json(health_data.get("services", {}))
    else:
        st.sidebar.error("⚠️ Backend Degraded")
except:
    st.sidebar.error("❌ Backend Offline")

# Main content
if page == "Threats Dashboard":
    st.header("🔍 Threat Detection Dashboard")
    
    # Auto-refresh
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
    
    if auto_refresh:
        placeholder = st.empty()
        while True:
            threats = fetch_threats()
            
            # Stats
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                critical = len([t for t in threats if t.get("severity") == "critical"])
                st.metric("Critical", critical, delta=None)
            with col2:
                high = len([t for t in threats if t.get("severity") == "high"])
                st.metric("High", high, delta=None)
            with col3:
                medium = len([t for t in threats if t.get("severity") == "medium"])
                st.metric("Medium", medium, delta=None)
            with col4:
                total = len(threats)
                st.metric("Total Threats", total, delta=None)
            
            # Threat list
            st.subheader("Recent Threats")
            for threat in threats[:20]:  # Show latest 20
                severity = threat.get("severity", "unknown")
                color = get_severity_color(severity)
                
                with st.expander(f"🔴 {severity.upper()} - {threat.get('threat_type', 'unknown')} - Pod: {threat.get('source_pod', 'unknown')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Threat ID:** {threat.get('id')}")
                        st.write(f"**Detected:** {threat.get('detected_at', 'unknown')}")
                        st.write(f"**Pod:** {threat.get('source_pod', 'N/A')}")
                        st.write(f"**Namespace:** {threat.get('source_namespace', 'N/A')}")
                    with col2:
                        st.write(f"**ML Score:** {threat.get('ml_score', 'N/A')}")
                        st.write(f"**Confidence:** {threat.get('confidence', 'N/A')}")
                        st.write(f"**Resolved:** {'✅' if threat.get('resolved') else '❌'}")
                    
                    st.write(f"**Description:** {threat.get('description', 'No description')}")
                    
                    # Get explanation
                    if st.button(f"Get Explanation", key=f"explain_{threat.get('id')}"):
                        try:
                            explain_response = requests.get(f"{API_BASE}/api/v1/explain/{threat.get('id')}")
                            if explain_response.status_code == 200:
                                explanation = explain_response.json()
                                st.info(f"**FRIDAY:** {explanation.get('explanation', 'No explanation available')}")
                        except Exception as e:
                            st.error(f"Error: {e}")
            
            time.sleep(5)
    else:
        threats = fetch_threats()
        st.json(threats)

elif page == "Actions Log":
    st.header("⚡ Remediation Actions")
    
    actions = fetch_actions()
    
    # Stats
    col1, col2, col3 = st.columns(3)
    with col1:
        executed = len([a for a in actions if a.get("executed")])
        st.metric("Executed", executed)
    with col2:
        pending = len([a for a in actions if not a.get("executed")])
        st.metric("Pending", pending)
    with col3:
        successful = len([a for a in actions if a.get("success")])
        st.metric("Successful", successful)
    
    # Actions list
    for action in actions[:20]:
        action_type = action.get("action_type", "unknown")
        risk_level = action.get("risk_level", "unknown")
        
        with st.expander(f"{action_type.upper()} - Risk: {risk_level.upper()} - Confidence: {action.get('confidence', 0):.2f}"):
            st.write(f"**Action ID:** {action.get('id')}")
            st.write(f"**Threat ID:** {action.get('threat_id')}")
            st.write(f"**Executed:** {'✅' if action.get('executed') else '⏳'}")
            st.write(f"**Success:** {action.get('success', 'N/A')}")
            st.write(f"**Requires Confirmation:** {'⚠️ Yes' if action.get('requires_confirmation') else '✅ No'}")

elif page == "System Health":
    st.header("💚 System Health")
    
    try:
        health_response = requests.get(f"{API_BASE}/health")
        if health_response.status_code == 200:
            health_data = health_response.json()
            st.json(health_data)
        else:
            st.error("Failed to fetch health data")
    except Exception as e:
        st.error(f"Error: {e}")

# Footer
st.markdown("---")
st.markdown('<p style="text-align: center; color: #666;">SentinelForge v0.1.0 - Phase 1 Prototype</p>', unsafe_allow_html=True)
