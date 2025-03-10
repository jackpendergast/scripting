def Get_Current_Username():
    import os
    print("The current user is",os.getlogin())


if __name__ == "__main__":
    Get_Current_Username()