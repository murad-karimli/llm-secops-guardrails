import argparse
from agent.core import SecureAgentEngine

def main():
    parser = argparse.ArgumentParser(description="LLM SecOps Guardrail Sandbox")
    parser.add_argument(
        "--mode", 
        choices=["vulnerable", "secure"], 
        default="secure",
        help="Run agent in baseline vulnerable mode or hardened secure mode"
    )
    args = parser.parse_args()

    print("=" * 65)
    print(f"   AI SecOps: LLM Prompt Injection & Guardrail Sandbox")
    print(f"   Engine: Ollama (llama3.2) | Active Mode: {args.mode.upper()}")
    print("=" * 65)
    print("[*] Type 'exit' or 'quit' to terminate session.\n")

    agent = SecureAgentEngine(mode=args.mode)

    while True:
        try:
            user_prompt = input("\n[User] > ")
            if user_prompt.strip().lower() in ["exit", "quit"]:
                break

            if not user_prompt.strip():
                continue

            print("[*] Evaluating prompt through pipeline...")
            reply = agent.chat(user_prompt)
            print(f"\n[Agent] >\n{reply}")

        except KeyboardInterrupt:
            print("\nTerminating session...")
            break

if __name__ == "__main__":
    main()