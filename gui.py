def choice(choice_list, help_text):    
    while True:
        print(help_text)
        for i in range(0,len(choice_list)):
            print('[{}] - {}'.format(str(i + 1), choice_list[i]))
        
        choice = int(input())
        if choice > 0 and choice <= len(choice_list):
            return choice_list[choice-1]
            
        print("Choice not in range ! Choose again...")
        
def ascii_art():
    print("""
     ___   ____    ____  __       _______     ___       __  ___ 
    /   \  \   \  /   / |  |     |   ____|   /   \     |  |/  / 
   /  ^  \  \   \/   /  |  |     |  |__     /  ^  \    |  '  /  
  /  /_\  \  \      /   |  |     |   __|   /  /_\  \   |    <   
 /  _____  \  \    /    |  `----.|  |____ /  _____  \  |  .  \  
/__/     \__\  \__/     |_______||_______/__/     \__\ |__|\__\ 
""")
    