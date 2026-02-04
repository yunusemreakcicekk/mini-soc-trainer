import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_training_data():
    with open(os.path.join(BASE_DIR, "training_lab", "scenarios.json"), encoding="utf-8") as f:
        scenarios = json.load(f)

    with open(os.path.join(BASE_DIR, "training_lab", "answers.json"), encoding="utf-8") as f:
        answers = json.load(f)

    with open(os.path.join(BASE_DIR, "training_lab", "feedback.json"), encoding="utf-8") as f:
        feedback = json.load(f)

    return scenarios, answers, feedback


def run_training_lab():
    scenarios, answers, feedback = load_training_data()

    print("DEBUG - Loaded scenarios:", scenarios)

    for scn_id, scenario in scenarios.items():
        print("\n" + "=" * 60)
        print(f"TRAINING SCENARIO: {scn_id}")
        print("=" * 60)

        print(f"Attack Type : {scenario['attack_type']}")
        print(f"Summary     : {scenario['summary']}")
        print(f"Severity    : {scenario['severity']}")
        print(f"Source IP   : {scenario['source_ip']}")

        user_choice = input(
            "\nIs this alert TRUE POSITIVE or FALSE POSITIVE? (TP/FP): "
        ).strip().upper()

        correct = answers[scn_id]["classification"]
        explanation = answers[scn_id]["reason"]

        if user_choice == "TP" and correct == "TRUE_POSITIVE":
            print("\n✅ Correct!")
        elif user_choice == "FP" and correct == "FALSE_POSITIVE":
            print("\n✅ Correct!")
        else:
            print("\n❌ Incorrect.")

        print("\n📘 Explanation:")
        print(explanation)

        print("\n🎓 Feedback:")
        print(feedback[scn_id][correct])


if __name__ == "__main__":
    run_training_lab()
