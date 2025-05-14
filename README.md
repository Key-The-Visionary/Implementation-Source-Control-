# Implementation-Source-Control-
This is the Implementation/Source Control for my Senior Capstone project.


Below is the Implementation/source Control for the dataset extractor:

    import json
    from tqdm import tqdm as pbar
    def extract_value(filepath, key_to_extract):
        """
        Extracts a specific value from a JSON file.

    Args:
        filepath (str): The path to the JSON file.
        key_to_extract (str): The key corresponding to the value to extract.

    Returns:
        The extracted value, or None if the key is not found.
    """
    try:
        with open(filepath, 'r') as file:
            data = json.load(file)
        return data[key_to_extract]
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except KeyError:
        print(f"Error: Key '{key_to_extract}' not found in the JSON data.")
        return None

    # Example usage:
    import os
    dir_path =r".\windows_emulation_trainset"
    dir_list= os.listdir(dir_path)
    # filepath = "example-ransomeware.json" 
    print(dir_list)
    count=0
    apihash_list=[]
      for each_dir in dir_list:
      #get the files' name
    if (each_dir =="report_clean"):
        list_file_names =os.listdir(dir_path+ '\\'+ each_dir)
        # print(list_file_names)
        # exit(0)
        for filename in pbar(list_file_names):
              
                
                with open( dir_path+ '\\'+ each_dir + '\\'+ filename, 'r') as file:
                    try:
                        data = json.load(file)
                        str_data=data[0]["apihash"]
                        if str_data[-4:]==".apk":
                            print(str_data)
                            print("folder name:"+ filename)
                            exit(0)
                        apihash_list.append(data[0]["apihash"])
                        count+=1
                    except:
                        continue
                
                if count>24000:
                    break
    count=0
            # if count>3000:
            #         break 
                
    print(apihash_list)# use panda dataframe to staore api hash as csv file
    # Save to CSV using pandas
    import pandas as pd

    df = pd.DataFrame(apihash_list, columns=['apihash'])
    df.to_csv("apihash_output2.csv", index=False)

    print("API hashes saved to 'apihash_output2.csv'")
    # key_to_extract = "apihash"
    # extracted_value = extract_value(filepath, key_to_extract)

    # if extracted_value:
    #     print(f"Extracted value for key '{key_to_extract}': {extracted_value}")
    # else:
    #     print("Value not found or an error occurred.")
  
  
  
  Below is the code for my LSTM Model used:


    import numpy as np
    import tensorflow as tf
    from tensorflow.keras.preprocessing.text import Tokenizer
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from keras.layers import LSTM, Dense,Input, Dropout, Embedding,  MaxPooling1D
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.models import Model
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import confusion_matrix
    from mlxtend.plotting import plot_confusion_matrix
    import pandas as pd
    import tsaug as ts
    from tsaug import TimeWarp, Drift
    from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
    import matplotlib.pyplot as plt

    max_length =0
      df = pd.read_csv(r'Merged_data.csv', names=["Apihash", "Label"], header=0)
      df =df.dropna()

    import nlpaug.augmenter.char as nac

    from sklearn.model_selection import train_test_split


    train_df, test_df = train_test_split(df, test_size=0.1, random_state=42)

    train_apihashes = train_df['Apihash'].tolist()
    test_apihashes  = test_df['Apihash'].tolist()


    def data_preprocessing(apihashes):
        global char_index, max_length
        tokenizer = Tokenizer(char_level=True, oov_token="<OOV>")
        tokenizer.fit_on_texts(apihashes)
    
    char_index = tokenizer.word_index

    
    sequences = tokenizer.texts_to_sequences(apihashes)
    
    max_length = max([len(seq) for seq in sequences])

    padded_sequences = pad_sequences(sequences,
                                    maxlen=max_length, 
                                    padding="pre")
    

    return padded_sequences


    def malware_lstm_model(X_train_len):
        embedding_layer=  Sequential([
        Embedding(input_dim=vocab_size, 
                  output_dim=embedding_dim, 
                  input_length=max_length),
        ])
    
    input_layer = Input(shape=(X_train_len,))
    embedding_output = embedding_layer(input_layer)

    lstm_layer = LSTM(64)(embedding_output)
    
    lstm_layer = Dropout(0.2)(lstm_layer)
   
    dense_output = Dense(1, activation='sigmoid')(lstm_layer) 
    model = Model(inputs=input_layer, outputs=dense_output,)
    return model



 
    X_train = data_preprocessing(train_apihashes)
    Y_train = np.array(train_df['Label'].astype(float))


    X_test = data_preprocessing(test_apihashes)
    Y_test = np.array(test_df['Label'].astype(float))


    embedding_dim = 32
    vocab_size = len(char_index) + 1


    X_train_len= len(X_train[0])
    model = malware_lstm_model(X_train_len)
    print(model.summary())
    model.compile(loss='binary_crossentropy', optimizer="Adam",
              metrics=['accuracy'])
    history = model.fit(X_train, Y_train, batch_size=1000,  
                    epochs=10, validation_data=(X_test, Y_test),
                    verbose=1)


    # 1. Get model predictions on test data
    y_pred_prob = model.predict(X_test)
    y_pred = (y_pred_prob > 0.5).astype("int32")  # Convert probabilities to binary labels

    # 2. Generate confusion matrix
    cm = confusion_matrix(Y_test, y_pred)

    # 3. Plot the confusion matrix using seaborn or sklearn
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign', 'Malware'], yticklabels=['Benign', 'Malware'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Confusion Matrix')
    plt.show()



Below is the Implementation/Source Control for Logistic regression model: 

    from sklearn.linear_model import LogisticRegression

    from sklearn.model_selection import train_test_split

    from sklearn.metrics import accuracy_score

    from sklearn.feature_extraction.text import TfidfVectorizer

    import pandas as pd

    import numpy as np

    from sklearn.metrics import confusion_matrix
    import seaborn as sns
    import matplotlib.pyplot as plt
 

    char_vectorizer = TfidfVectorizer(

      sublinear_tf=True,

      strip_accents='unicode',

      analyzer='char',

    

      ngram_range=(2, 6),

      max_features=50000)

 

    log_reg_model = LogisticRegression(solver='liblinear')  

    df = pd.read_csv(r'Merged_data.csv', names=["Apihash", "Label"], header=0)

    df =df.dropna()



    train_df, test_df = train_test_split(df, test_size=0.1, random_state=42)

    train_data = train_df['Apihash']

    test_data = test_df['Apihash']

    all_text = pd.concat([train_data, test_data])

    char_vectorizer.fit(all_text)

    X_train = char_vectorizer.transform(train_data)

    X_test= char_vectorizer.transform(test_data)

 

    y_train = np.array(train_df['Label'].astype(float))

    y_test = np.array(test_df['Label'].astype(float))



    log_reg_model.fit(X_train, y_train)

 

    y_pred = log_reg_model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    print(f"Accuracy: {accuracy:.2f}")

    # Generate the confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    # Plot the confusion matrix
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Benign', 'Malware'], 
                yticklabels=['Benign', 'Malware'])

    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('Confusion Matrix - Logistic Regression')
    plt.show()






