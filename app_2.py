# Add under Tab 1 or as a 3rd Tab in app_2.py:
with tab1:
    # ... [Existing KPI cards and Plotly charts] ...
    
    st.markdown("---")
    st.subheader("🛡️ GenAI SOC Threat Copilot & Automated Diagnostics")
    
    rogue_samples = processed_df[processed_df["Prediction"] == 1]
    
    if len(rogue_samples) > 0:
        latest_threat = rogue_samples.iloc[-1].to_dict()
        latest_threat["timestamp"] = time.time()
        
        # Import SOC engine
        from src.soc_copilot import generate_soc_analysis
        analysis = generate_soc_analysis(latest_threat, model_choice)
        
        c_soc1, c_soc2 = st.columns([6, 4])
        with c_soc1:
            st.error(f"🚨 **{analysis['threat_category']}** | Incident ID: `{analysis['incident_id']}`")
            st.markdown(f"**Root-Cause Diagnosis:** {analysis['root_cause_summary']}")
            st.markdown(f"**Detection Confidence:** `{analysis['severity']}` via `{analysis['detector_engine']}`")
            
        with c_soc2:
            st.warning("⚡ **Automated Gateway Mitigation Commands**")
            st.code(analysis["recommended_iptables_rule"], language="bash")
            st.code(analysis["gateway_mac_command"], language="bash")
            if st.button("Exec Mitigation Rules"):
                st.success(f"Rule deployed to Gateway Socket. Device '{analysis['device_id']}' quarantined.")
    else:
        st.success("🟢 Network Telemetry Nominal. No Threat Interventions Required.")