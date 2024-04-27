import os
import platform
try:
    import winsound
except:
    pass
import curses
import signal

def display_text(stdscr, text, sound_file):
    # Clear the screen
    stdscr.clear()

    # Get terminal dimensions
    height, width = stdscr.getmaxyx()

    # Calculate the number of lines needed to display the text
    lines = text.split('\n')
    num_lines = len(lines)

    # Calculate the number of pages
    page_size = height - 1  # Leave one line for "Press q to quit"
    num_pages = (num_lines + page_size - 1) // page_size

    # Display text page by page
    current_page = 0
    while True:
        stdscr.clear()

        # Get updated terminal dimensions
        height, width = stdscr.getmaxyx()

        # Calculate start and end indexes for the current page
        start_index = current_page * page_size
        end_index = min(start_index + page_size, num_lines)

        # Display the current page of text
        for i in range(start_index, end_index):
            stdscr.addstr(i - start_index, 0, lines[i][:width-1])

        # Add a message to indicate how to quit
        stdscr.addstr(height - 1, 0, "Press 'q' to quit. Use arrow keys to scroll.")

        # Refresh the screen
        stdscr.refresh()

        # Wait for user input
        key = stdscr.getch()
        
        if key == ord('q'):

            # Windows
            if platform.system() == 'Windows':
                winsound.PlaySound(None, winsound.SND_PURGE)
            # Linux
            elif platform.system() == "Linux":
                os.system("killall aplay {}&".format(sound_file))
            # Mac
            else:
                os.system("killall afplay {}&".format(sound_file))
                    
            break

        elif key == curses.KEY_DOWN:
            current_page = min(current_page + 1, num_pages - 1)
        elif key == curses.KEY_UP:
            current_page = max(current_page - 1, 0)

def main(stdscr):
    # Turn off cursor blinking
    curses.curs_set(0)

    # Read text from a file (you can replace this with your text source)
    with open("lyrics.txt", "r") as file:
        text = file.read()

    # Set up signal handler for window resize
    signal.signal(signal.SIGWINCH, lambda signum, frame: curses.update_lines_cols())

    sound_file = "hello.mp3"

    # Windows
    if platform.system() == 'Windows':
        winsound.PlaySound(sound_file, winsound.SND_ASYNC)
    # Linux
    elif platform.system() == "Linux":
        os.system("aplay -q {}&".format(sound_file))
    # Mac
    else:
        os.system("afplay {}&".format(sound_file))

    # Display text
    display_text(stdscr, text, sound_file)

def karaoke():
    curses.wrapper(main)
