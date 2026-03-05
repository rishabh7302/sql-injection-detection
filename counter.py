attack_count = 0

def increment_attack():
    global attack_count
    attack_count += 1
    return attack_count

def get_attack_count():
    return attack_count