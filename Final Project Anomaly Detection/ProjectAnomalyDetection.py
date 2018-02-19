import pandas
col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]
kdd_data_10percent = pandas.read_csv("G:\DataSet\kddcup.data_10_percent\kddcup.data_10_percent_corrected", header=None, names = col_names)
#print(kdd_data_10percent['label'].value_counts())
num_features = [
    
    "src_bytes",#5
    "dst_bytes",#6
    "num_compromised",#13
    "count",#23
    "srv_count",#24
    "serror_rate",#25
    "same_srv_rate",#29
    "diff_srv_rate",#30
    "dst_host_count",#32
    "dst_host_srv_count",#33
     "dst_host_same_srv_rate",#34
    "dst_host_diff_srv_rate",#35
    "dst_host_same_src_port_rate",#36
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate"
]
features = kdd_data_10percent[num_features].astype(float)
#from sklearn.preprocessing import MinMaxScaler
#features.apply(lambda x: MinMaxScaler().fit_transform(x))

import numpy as np
import skfuzzy as fuzz
import skfuzzy.control as ctrl
features = np.asarray(features).tolist()
labels = np.asarray(kdd_data_10percent["label"].str.split(',')).tolist()

#print(features[1][33])
#print(labels)

#####DoS########

src_bytes = ctrl.Antecedent(np.arange(0, 54541, 1), 'src_bytes')
dst_bytes = ctrl.Antecedent(np.arange(0, 54541, 1), 'dst_bytes')
num_compromised = ctrl.Antecedent(np.arange(0, 886, 1), 'num_compromised')
count = ctrl.Antecedent(np.arange(0, 551, 1), 'count')
srv_count = ctrl.Antecedent(np.arange(0, 551, 1), 'srv_count')
serror_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'serror_rate')
dst_host_srv_count = ctrl.Antecedent(np.arange(0, 256, 1), 'dst_host_srv_count')
dst_host_same_src_port_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'dst_host_same_src_port_rate')
dst_host_srv_diff_host_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'dst_host_srv_diff_host_rate')
dst_host_serror_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'dst_host_serror_rate')
same_srv_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'same_srv_rate')
diff_srv_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'diff_srv_rate')
dst_host_count = ctrl.Antecedent(np.arange(0, 256, 1), 'dst_host_count')
dst_host_same_srv_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'dst_host_same_srv_rate')
dst_host_diff_srv_rate = ctrl.Antecedent(np.arange(0, 101, 1), 'dst_host_diff_srv_rate')
types = ctrl.Consequent(np.arange(0, 101, 1), 'types')



src_bytes['vvlow'] = fuzz.trimf(src_bytes.universe, [0, 50, 100])
src_bytes['vlow'] = fuzz.trimf(src_bytes.universe, [75,125,500])
src_bytes['low'] = fuzz.trimf(src_bytes.universe, [200,500,1000])
src_bytes['vvmeduim'] = fuzz.trimf(src_bytes.universe, [500, 1000, 5000])
src_bytes['vmeduim'] = fuzz.trimf(src_bytes.universe, [1000,5000,25000])
src_bytes['meduim'] = fuzz.trimf(src_bytes.universe, [5000,25000,54540])
src_bytes['high'] = fuzz.trimf(src_bytes.universe, [25000, 54540, 54540])
src_bytes.view()

dst_bytes['vvlow'] = fuzz.trimf(dst_bytes.universe, [0, 50, 100])
dst_bytes['vlow'] = fuzz.trimf(dst_bytes.universe, [75,125,500])
dst_bytes['low'] = fuzz.trimf(dst_bytes.universe, [200,500,1000])
dst_bytes['vvmeduim'] = fuzz.trimf(dst_bytes.universe, [500, 1000, 5000])
dst_bytes['vmeduim'] = fuzz.trimf(dst_bytes.universe, [1000,5000,25000])
dst_bytes['meduim'] = fuzz.trimf(dst_bytes.universe, [5000,25000,54540])
dst_bytes['high'] = fuzz.trimf(dst_bytes.universe, [25000, 54540, 54540])
dst_bytes.view()

num_compromised['vlow'] = fuzz.trimf(num_compromised.universe, [0,100,175])
num_compromised['low'] = fuzz.trimf(num_compromised.universe, [100,200,300])
num_compromised['vvmeduim'] = fuzz.trimf(num_compromised.universe, [225, 300, 400])
num_compromised['vmeduim'] = fuzz.trimf(num_compromised.universe, [300,400,450])
num_compromised['meduim'] = fuzz.trimf(num_compromised.universe, [375,500,600])
num_compromised['high'] = fuzz.trimf(num_compromised.universe, [550, 885, 885])
num_compromised.view()

count['vvlow'] = fuzz.trimf(count.universe, [0, 50, 100])
count['vlow'] = fuzz.trimf(count.universe, [75,125,175])
count['low'] = fuzz.trimf(count.universe, [150,200,250])
count['vvmeduim'] = fuzz.trimf(count.universe, [225, 275, 325])
count['vmeduim'] = fuzz.trimf(count.universe, [300,350,400])
count['meduim'] = fuzz.trimf(count.universe, [375,425,475])
count['high'] = fuzz.trimf(count.universe, [450, 500, 550])
#count.view()

srv_count['vvlow'] = fuzz.trimf(srv_count.universe, [0, 50, 100])
srv_count['vlow'] = fuzz.trimf(srv_count.universe, [75,125,175])
srv_count['low'] = fuzz.trimf(srv_count.universe, [150,200,250])
srv_count['vvmeduim'] = fuzz.trimf(srv_count.universe, [225, 275, 325])
srv_count['vmeduim'] = fuzz.trimf(srv_count.universe, [300,350,400])
srv_count['meduim'] = fuzz.trimf(srv_count.universe, [375,425,475])
srv_count['high'] = fuzz.trimf(srv_count.universe, [450, 500, 550])
#srv_count.view()

serror_rate['low'] = fuzz.trimf(serror_rate.universe, [0, 25, 50])
serror_rate['meduim'] = fuzz.trimf(serror_rate.universe, [25, 50, 75])
serror_rate['high'] = fuzz.trimf(serror_rate.universe, [50,75,100])
#serror_rate.view()

dst_host_srv_count['low'] = fuzz.trimf(dst_host_srv_count.universe, [0, 0, 128])
dst_host_srv_count['medium'] = fuzz.trimf(dst_host_srv_count.universe, [0, 128, 255])
dst_host_srv_count['high'] = fuzz.trimf(dst_host_srv_count.universe, [128,255,255])
#dst_host_srv_count.view()

dst_host_same_src_port_rate['low'] = fuzz.trimf(dst_host_same_src_port_rate.universe, [0, 25, 50])
dst_host_same_src_port_rate['meduim'] = fuzz.trimf(dst_host_same_src_port_rate.universe, [25, 50, 75])
dst_host_same_src_port_rate['high'] = fuzz.trimf(dst_host_same_src_port_rate.universe, [50,75,100])
#dst_host_same_src_port_rate.view()

dst_host_srv_diff_host_rate['low'] = fuzz.trimf(dst_host_srv_diff_host_rate.universe, [0, 25, 50])
dst_host_srv_diff_host_rate['meduim'] = fuzz.trimf(dst_host_srv_diff_host_rate.universe, [25, 50, 75])
dst_host_srv_diff_host_rate['high'] = fuzz.trimf(dst_host_srv_diff_host_rate.universe, [50,75,100])
#dst_host_srv_diff_host_rate.view()

dst_host_serror_rate['low'] = fuzz.trimf(dst_host_serror_rate.universe, [0, 25, 50])
dst_host_serror_rate['meduim'] = fuzz.trimf(dst_host_serror_rate.universe, [25, 50, 75])
dst_host_serror_rate['high'] = fuzz.trimf(dst_host_serror_rate.universe, [50,75,100])
#dst_host_serror_rate.view()

same_srv_rate['low'] = fuzz.trimf(same_srv_rate.universe, [0, 25, 50])
same_srv_rate['meduim'] = fuzz.trimf(same_srv_rate.universe, [25, 50, 75])
same_srv_rate['high'] = fuzz.trimf(same_srv_rate.universe, [50,75,100])
#same_srv_rate.view()

diff_srv_rate['low'] = fuzz.trimf(diff_srv_rate.universe, [0, 25, 50])
diff_srv_rate['meduim'] = fuzz.trimf(diff_srv_rate.universe, [25, 50, 75])
diff_srv_rate['high'] = fuzz.trimf(diff_srv_rate.universe, [50,75,100])
#diff_srv_rate.view()

dst_host_count['vlow'] = fuzz.trimf(dst_host_count.universe, [0,25,50])
dst_host_count['low'] = fuzz.trimf(dst_host_count.universe, [25,50,75])
dst_host_count['vvmeduim'] = fuzz.trimf(dst_host_count.universe, [75, 100, 125])
dst_host_count['vmeduim'] = fuzz.trimf(dst_host_count.universe, [100,125,150])
dst_host_count['meduim'] = fuzz.trimf(dst_host_count.universe, [125,150,175])
dst_host_count['high'] = fuzz.trimf(dst_host_count.universe, [150,175, 200])
dst_host_count['vhigh'] = fuzz.trimf(dst_host_count.universe, [175,200, 225])
dst_host_count['vvhigh'] = fuzz.trimf(dst_host_count.universe, [200,225,255])
#dst_host_count.view()

dst_host_same_srv_rate['low'] = fuzz.trimf(dst_host_same_srv_rate.universe, [0, 25, 50])
dst_host_same_srv_rate['meduim'] = fuzz.trimf(dst_host_same_srv_rate.universe, [25, 50, 75])
dst_host_same_srv_rate['high'] = fuzz.trimf(dst_host_same_srv_rate.universe, [50,75,100])
#dst_host_same_srv_rate.view()

dst_host_diff_srv_rate['low'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [0, 25, 50])
dst_host_diff_srv_rate['meduim'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [25, 50, 75])
dst_host_diff_srv_rate['high'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [50,75,100])
#dst_host_diff_srv_rate.view()

same_srv_rate['low'] = fuzz.trimf(same_srv_rate.universe, [0, 25, 50])
same_srv_rate['meduim'] = fuzz.trimf(same_srv_rate.universe, [25, 50, 75])
same_srv_rate['high'] = fuzz.trimf(same_srv_rate.universe, [50,75,100])
#same_srv_rate.view()

diff_srv_rate['low'] = fuzz.trimf(diff_srv_rate.universe, [0, 25, 50])
diff_srv_rate['meduim'] = fuzz.trimf(diff_srv_rate.universe, [25, 50, 75])
diff_srv_rate['high'] = fuzz.trimf(diff_srv_rate.universe, [50,75,100])
#diff_srv_rate.view()

dst_host_count['vlow'] = fuzz.trimf(dst_host_count.universe, [0,25,50])
dst_host_count['low'] = fuzz.trimf(dst_host_count.universe, [25,50,75])
dst_host_count['vvmeduim'] = fuzz.trimf(dst_host_count.universe, [75, 100, 125])
dst_host_count['vmeduim'] = fuzz.trimf(dst_host_count.universe, [100,125,150])
dst_host_count['meduim'] = fuzz.trimf(dst_host_count.universe, [125,150,175])
dst_host_count['high'] = fuzz.trimf(dst_host_count.universe, [150,175, 200])
dst_host_count['vhigh'] = fuzz.trimf(dst_host_count.universe, [175,200, 225])
dst_host_count['vvhigh'] = fuzz.trimf(dst_host_count.universe, [200,225,255])
#dst_host_count.view()

dst_host_same_srv_rate['low'] = fuzz.trimf(dst_host_same_srv_rate.universe, [0, 25, 50])
dst_host_same_srv_rate['meduim'] = fuzz.trimf(dst_host_same_srv_rate.universe, [25, 50, 75])
dst_host_same_srv_rate['high'] = fuzz.trimf(dst_host_same_srv_rate.universe, [50,75,100])
#dst_host_same_srv_rate.view()

dst_host_diff_srv_rate['low'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [0, 25, 50])
dst_host_diff_srv_rate['meduim'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [25, 50, 75])
dst_host_diff_srv_rate['high'] = fuzz.trimf(dst_host_diff_srv_rate.universe, [50,75,100])
#dst_host_diff_srv_rate.view()

types = ctrl.Consequent(np.arange(0, 101, 1), 'types')
types['Normal'] = fuzz.trimf(types.universe, [0, 0, 50])
#types['Risk'] = fuzz.trimf(types.universe, [25, 50, 75])
types['Attack'] = fuzz.trimf(types.universe, [50,100,100])
#types.view()

rule1 = ctrl.Rule(dst_host_srv_count['low'] | dst_host_srv_count['high'] & dst_bytes['high'], types['Normal'])
rule2 = ctrl.Rule(src_bytes['high'], types['Normal'])
rule3 = ctrl.Rule(srv_count['high'] & src_bytes['low'] | src_bytes['high'], types['Normal'])
rule4 = ctrl.Rule(num_compromised['high'], types['Normal'])
rule5 = ctrl.Rule(serror_rate['high'], types['Normal'])
rule6 = ctrl.Rule(dst_host_srv_count['high'], types['Normal'])
rule7 = ctrl.Rule(dst_host_same_src_port_rate['high'], types['Normal'])
rule8 = ctrl.Rule(dst_host_srv_diff_host_rate['high'], types['Normal'])
rule9 = ctrl.Rule(dst_host_serror_rate['high'], types['Normal'])
rule10 = ctrl.Rule(count['high'], types['Normal'])
rule11 = ctrl.Rule(count['vlow'] & dst_host_same_srv_rate['low'] & dst_host_diff_srv_rate['low'] & same_srv_rate['low'] & diff_srv_rate['low'] , types['Attack'])
rule12 = ctrl.Rule(count['low'] & dst_host_same_srv_rate['low'] & dst_host_diff_srv_rate['low'] & same_srv_rate['low'] & diff_srv_rate['low'] , types['Attack'])
rule13 = ctrl.Rule(count['meduim'] & same_srv_rate['high'] & diff_srv_rate['low'] &  dst_host_same_srv_rate['low'] & dst_host_diff_srv_rate['low'], types['Attack'])
rule14 = ctrl.Rule(count['high'] & same_srv_rate['high'] & diff_srv_rate['low'] &  dst_host_same_srv_rate['low'] & dst_host_diff_srv_rate['low'], types['Attack'])
rule15 = ctrl.Rule(count['meduim'] & same_srv_rate['high'] & diff_srv_rate['low'] & dst_host_same_srv_rate['meduim']  & dst_host_diff_srv_rate['low'], types['Attack'])
rule16 = ctrl.Rule(count['high'] & same_srv_rate['high'] & diff_srv_rate['low'] & dst_host_same_srv_rate['meduim']  & dst_host_diff_srv_rate['low'], types['Attack'])
rule17 = ctrl.Rule(dst_host_count['vvhigh'] , types['Attack'])

typping_ctrl = ctrl.ControlSystem([rule1,rule2,rule3,rule4,rule5,rule6,rule7,rule8,rule9,rule10,rule11,rule12,rule13,rule14,rule15,rule16,rule17])
typping = ctrl.ControlSystemSimulation(typping_ctrl)

f1 = 0;f2 =0;
Att = 0;
Nor = 0;
for i in range(1000):
    #print(features[i][0])
    #print(features[i][1])
    #print(features[i][2])
    #print(features[i][3])
    #print(features[i][4])
    #print(features[i][5])
    #print(features[i][6])
    #print(features[i][7])
    #print(features[i][8])
    #print(features[i][9])
    #print(features[i][10])
    #print(features[i][11])
    #print(features[i][12])
    #print(features[i][13])
    #print(features[i][14])

    if(features[i][0] >= 54541 ):
        f1 = 54540
    else:
        f1 = features[i][0]
    if(features[i][1] >= 54541 ):
        f2 = 54540
    else:
        f2 = features[i][1]
        
    typping.input['src_bytes'] = f1
    typping.input['dst_bytes'] = f2
    typping.input['num_compromised'] = features[i][2]
    typping.input['count'] = features[i][3]
    typping.input['srv_count'] = features[i][4]
    typping.input['serror_rate'] = features[i][5]*100
    typping.input['same_srv_rate'] = features[i][6]*100
    typping.input['diff_srv_rate'] = features[i][7]*100
    typping.input['dst_host_count'] = features[i][8]
    typping.input['dst_host_srv_count'] = features[i][9]
    typping.input['dst_host_same_srv_rate'] = features[i][10]*100
    typping.input['dst_host_diff_srv_rate'] = features[i][11]*100
    typping.input['dst_host_same_src_port_rate'] = features[i][12]*100
    typping.input['dst_host_srv_diff_host_rate'] = features[i][13]*100
    typping.input['dst_host_serror_rate'] = features[i][14]*100
        #print(features[i][0],features[i][1])
    typping.compute()
    #print("Values :",typping.output['types'])
    types.view(sim=typping)
    
    if(typping.output['types'] > 50): 
        Att += 1
    else:
        Nor +=1

print(" Attacks :",Att,"\n","Normal :",Nor)

        
    
     
#print(DoSFeatures)

#print(classifier.predict([[0.0, 239.0, 1236.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,0,0,0,0,0,2,1,1.00,1.00,0.00,0.00,0.50,1.00,0.00, 324.0, 19.0, 1.0, 0.0, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0]]))
#nmap   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,1,1.00,1.00,0.00,0.00,0.50,1.00,0.00,14,1,0.07,0.71,0.50,0.00,0.50,1.00,0.00,0.00
#      0,#2tcp,#3private,#4SH,0,0,0,0,0,(10)0,0,#0,0,0,0,0,0,0,0,(20)0,#0,#0,2,1,1.00,1.00,0.00,0.00,0.50,1.00,0.00,14,1,0.07,0.71,0.50,0.00,0.50,1.00,0.00,0.00
#normal  0.0, 239.0, 1236.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 8.0, 8.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 324.0, 19.0, 1.0, 0.0, 0.05, 0.0, 0.0, 0.0, 0.0, 0.0
