from email_analyzer_gui import EmailAnalyzerGui
from gui import gui
from logic import logic

if __name__ == "__main__":
    # gui = EmailAnalyzerGui()
    gui = gui()
    logic = logic(gui)
