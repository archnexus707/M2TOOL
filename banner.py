import time
import os

# Define the dancing girl frames
frames = [
    r"""
     ♡
    /|\
    / \
    """,
    r"""
     ♡
    <|>
    / \
    """,
    r"""
     ♡
    /|\
    / \
    """,
    r"""
     ♡
    <|>
    / \
    """
]

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    try:
        while True:
            for frame in frames:
                clear_screen()
                print(frame)
                time.sleep(0.2)  # Adjust the speed of the animation
    except KeyboardInterrupt:
        print("\nDancing girl stopped. Goodbye!")

if __name__ == "__main__":
    main()