import numpy as np
from sklearn.externals import joblib
import re
from flask import Flask,render_template,request

app=Flask(__name__)

def preprocess(name):
    features=[]
    #check features of phishing url or not
    #ip address or not
    if(len(re.findall("^[0-9]+\.[0-9]+\.[0-9]",name))>=1):
        features.append(-1)
    else:
        features.append(1)
    #url length
    url_length=len(name)
    if(url_length<54):
        features.append(1)
    elif(url_length>75):
        features.append(-1)
    else:
        features.append(0)
    # @ present or not
    b=re.search("@",name)
    if(b):
        features.append(-1)
    else:
        features.append(1)
    # check no. of subdomain
    if(len(re.findall('\.',name))==1):
        features.append(1)
    elif(len(re.findall('\.',name))==2):
        features.append(0)
    else:
        features.append(-1)
    # '//' present more than twice
    c=0
    b=name.split("/")
    for j in b:
        if (j==''):
            c=c+1
    if(c>1):
        features.append(-1)
    else:
        features.append(1)
    # https present
    if(name.startswith('https')==True):
        features.append(1)
    else :
        features.append(-1) 
    #Domain_registeration_length
    import whois
    
    dns=1
    try:
        whois_response = whois.whois(name)
        expiration_date = whois_response.expiration_date
        registration_length = 0
        try:
            expiration_date = min(expiration_date)
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            registration_length = abs((expiration_date - today).days)
            if (registration_length / 365 <= 1):
                features.append(-1)
            else:
                features.append(1)
        except:
            features.append(-1)    
    except:
        dns=-1
        
    # age_of_domain
    try:
        response = requests.get(url)
        
    except:
        response = ""
        
    if (response == ""):
        features.append(-1)
    else:
        try:
            registration_date = re.findall(r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
            if (diff_month(date.today(), date_parse(registration_date)) >= 6):
                features.append(-1)
            else:
                features.append(1)
        except:
                features.append(1)

    # DNSRecord
    
    if (dns == -1):
        features.append(-1)
    else:
        if (registration_length / 365 <= 1):
            features.append(-1)
        else:
            features.append(1)
    return features
@app.route('/')
def welcome():
    return render_template('welcome.html')
@app.route('/predict',methods=['POST'])
def predict():
    if (request.method == "POST"):
        name=request.form['name']
        clf3=joblib.load('model2.joblib')
        features=preprocess(name)
        features=np.array(features).reshape(1,-1)
        if(clf3.predict(features)[0]==-1):
            bot=name+"may be a phishing site. Continue Own your own risk."
        else:
            bot=name+"is not phishing."
    else:
        bot="Please go back and try again"
    return render_template('predict.html',bot=bot)
if __name__ == "__main__":
    app.run(debug=True,port=5000)