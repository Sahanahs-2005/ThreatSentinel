from security import inspect_message, inspect_response
from local_ai import get_ai_response


def main():
    print("\n" + "=" * 50)
    print("          THREATSENTINEL AI CHATBOT")
    print("=" * 50)
    print("AI Model: Llama 3.2 1B (Local Ollama)")
    print("Security: Input and output inspection")
    print("Type 'exit' to quit.")
    print("=" * 50)

    while True:
        try:
            user_message = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nThreatSentinel closed.")
            break

        if user_message.lower() == "exit":
            print("ThreatSentinel closed.")
            break

        if not user_message:
            print("Please enter a message.")
            continue

        # Step 1: Inspect the user's message.
        input_result = inspect_message(user_message)
        input_action = input_result["action"]

        print(f"\n[Input Security: {input_action}]")
        print(f"[Reason: {input_result['reason']}]")

        # Step 2: Stop blocked or quarantined messages.
        if input_action != "ALLOW":
            print("[ThreatSentinel] Message was not sent to the AI.")
            continue

        # Step 3: Generate a response using local Ollama.
        print("\n[ThreatSentinel] Generating response...")
        ai_response = get_ai_response(user_message)

        # Step 4: Inspect the AI response.
        if ai_response.startswith("AI connection error:") or \
                ai_response.startswith("Unexpected AI response:"):
            print(f"\n{ai_response}")
            continue

        output_result = inspect_response(ai_response)

        print(f"\n[Output Security: {output_result['action']}]")
        print(f"[Reason: {output_result['reason']}]")

        # Step 5: Display only an allowed response.
        if output_result["action"] == "ALLOW":
            print(f"\nThreatSentinel AI: {output_result['response']}")
        else:
            print("\nThreatSentinel AI: Response hidden for security reasons.")


if __name__ == "__main__":
    main()