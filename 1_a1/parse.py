for name in open("./usernames.txt", "r"):
    name = name.strip()
    for line in open("./vpn.log", "r"):
        line = line.strip()
        if "Node," in line:
            print(line)
            continue
        if name in line:
            print(line)
            
    print("="*30)
