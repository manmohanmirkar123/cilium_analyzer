import streamlit as st
import os
import tempfile
import main

st.set_page_config(page_title="Cilium Elite Analyzer", layout="wide")

st.title("🛡️ Cilium Manifest Elite Analyzer")
st.markdown("""
Upload your Cilium **DaemonSet** or **ConfigMap** YAML files to scan for:
- Security Risks
- Performance Tuning
- Reliability Issues
- Best Practices
""")

uploaded_files = st.file_uploader("Choose YAML files", accept_multiple_files=True, type=['yaml', 'yml'])

if st.button("Run Analysis", type="primary"):
    if uploaded_files:
        # Reset previous state
        main.reset_analysis()
        
        temp_paths = []
        # Save uploaded files to temp disk so main.py can read them
        for uploaded_file in uploaded_files:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as tmp:
                tmp.write(uploaded_file.getvalue())
                temp_paths.append(tmp.name)
        
        # Run the analysis logic
        with st.spinner('Analyzing manifests...'):
            main.scan_paths(temp_paths)
        
        # Calculate Score
        health_score = max(0, 100 - main.TOTAL_SCORE)
        
        # Display Score
        col1, col2 = st.columns([1, 3])
        with col1:
            st.metric("Cilium Health Score", f"{health_score}/100", delta=health_score-100)
        
        # Display Findings
        st.divider()
        
        categories = {
            "SECURITY": "🔴 Security",
            "RELIABILITY": "🟠 Reliability",
            "PERFORMANCE": "🔵 Performance",
            "BEST-PRACTICE": "🟢 Best Practices"
        }

        for key, label in categories.items():
            with st.expander(label, expanded=True):
                findings = main.FINDINGS.get(key, [])
                if findings:
                    for f in findings:
                        st.write(f"- {f}")
                else:
                    st.caption("No issues found.")

        # Cleanup temp files
        for p in temp_paths:
            try:
                os.remove(p)
            except OSError:
                pass
    else:
        st.warning("Please upload at least one YAML file.")