import csv
import Feature_extraction as urlfeature
import trainer as tr


def resultwriter(feature, output_dest):
    flag = True
    print(feature)
    
    with open(output_dest, 'w') as csvfile:        
       
        flag=True
        for item in feature:
            writer = csv.DictWriter(csvfile,fieldnames=item[1].keys())
            if flag:
                writer.writeheader()
                flag=False
            writer.writerow(item[1])

        





def process_URL_list(file_dest, output_dest):
    feature = []
    with open(file_dest) as file:
        for line in file:
            url = line.split(',')[0].strip()
            malicious_bool = line.split(',')[1].strip()
            if url != '':
                print('working on: ' + url)
                ret_dict = urlfeature.feature_extract(url)
                ret_dict['malicious'] = malicious_bool
                feature.append([url, ret_dict]);
    resultwriter(feature, output_dest)


def process_test_list(file_dest, output_dest):
    feature = []
    with open(file_dest) as file:
        for line in file:
            url = line.strip()
            if url != '':
                print('working on: ' + url)
                ret_dict = urlfeature.feature_extract(url)
                feature.append([url, ret_dict]);
    resultwriter(feature, output_dest)
    # return feature


# change
def process_test_url(url,output_dest):
    feature = []
    url = url.strip()
    if url != '':
        print('working on: ' + url)  # showoff
        ret_dict = urlfeature.feature_extract(url)
        feature.append([url, ret_dict]);
        # feature.append(url)
        # feature.append(ret_dict)
        # print(feature)
    resultwriter(feature, output_dest)
    # return feature


def main():
    process_URL_list('URL.txt', 'url_features.csv')
    # process_test_list("query.txt",'query_features.csv')
    tr.train('url_features.csv', 'url_features.csv')  # arguments:(input_training feature,test/query traning features)
    tr.train('url_features.csv', 'query_features.csv')
    # testing with urls in query.txt


print("main is running......")