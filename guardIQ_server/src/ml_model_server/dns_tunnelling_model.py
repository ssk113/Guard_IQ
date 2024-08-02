from tensorflow.keras.models import load_model
import math
import os
script_dir = os.path.dirname(__file__)

# 

def load_ml_model():
    # load model 
    model = load_model(os.path.join(script_dir, "dns_tunneling_ml.h5"))
    return model

ff = load_ml_model()

tokenizer = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

def extract_single_value(variable):
    if isinstance(variable, list):
        if len(variable) == 1:
            return extract_single_value(variable[0])
        else:
            raise ValueError("The provided list has more than one element.")
    else:
        return variable

def count_vector(url) -> list:
    tmp = []
    for i in range(96):
        tmp.append(0)
    for i in url:
        if (i in tokenizer):
            tmp[tokenizer.index(i)] += 1
    return tmp

def entropy_calculator(url) -> float:
    if not url:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(url.count(chr(x)))/len(url)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy

def calculate_length(url) -> int:
  if not url:
    return 0
  return len(url)

def isDNSTunneling(custom_dns):

    custom_temp = count_vector(custom_dns)
    custom_temp[94] = float(entropy_calculator(custom_dns))
    custom_temp[95] = float(calculate_length(custom_dns))

    x_custom = [custom_temp,]


    y_custom = ff.predict(x_custom)
    probability = 1
    result = ""
    if y_custom[0,0] < 0.5 :
        probability = (1-y_custom[0,0])*100
        result = 0
    else:
        probability = y_custom[0,0]*100
        result = 1

    return (result, probability)

def dns_ml_model_predict(query_name):
    try:
        received_string = query_name
        my_dns = '{!r}'.format(received_string)
        print('\n...ML Model Detection initiated\nReceived string:', my_dns)

        # Process the string (you can perform any logic here)
        # For simplicity, let's create a sample tuple as a response
        return isDNSTunneling(my_dns)
    
    except:
        print(f"ML Model cannot resolve the dns {received_string}")
        return 1
