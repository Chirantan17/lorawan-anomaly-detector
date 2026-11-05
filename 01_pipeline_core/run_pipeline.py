# run_pipeline.py
import os
import sys
import subprocess

def run_step(description, command):
    print(f"\n🚀 [STEP] {description}...")
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        print(f"❌ Error during step: {description}")
        sys.exit(1)

def main():
    print("=" * 60)
    print("   LoRaWAN Real-Time Security Engine: End-to-End Orchestrator")
    print("=" * 60)

    # 1. Initialize SQLite Database Tables
    print("\n📦 Initializing Database...")
    from database import init_db
    init_db()
    print("✅ Database initialized successfully.")

    # 2. Check or Generate Dataset
    if not os.path.exists("phase1_lorawan_100k.csv"):
        run_step("Generating 100k synthetic LoRaWAN telemetry dataset", f"{sys.executable} generate_data.py")
    else:
        print("✅ Dataset 'phase1_lorawan_100k.csv' found.")

    # 3. Check or Train ML Models
    if not os.path.exists("lorawan_models_bundle.pkl"):
        run_step("Training ML Ensemble models (XGBoost, Isolation Forest, Random Forest)", f"{sys.executable} train.py")
    else:
        print("✅ Model bundle 'lorawan_models_bundle.pkl' found.")

    # 4. Execute Test Suite using the active Python executable
    run_step("Executing Unit & Integration Test Suite", f"{sys.executable} -m pytest test_server.py")

    # 5. Launch Application Server
    print("\n🌐 Starting FastAPI Server & Gateway Listeners...")
    run_step("Launching Application Server", f"{sys.executable} server.py")

if __name__ == "__main__":
    main()