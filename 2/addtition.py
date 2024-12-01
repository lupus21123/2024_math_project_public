import pandas as pd

def calculate_correlations(csv_file, target_column="label"):
    df = pd.read_csv(csv_file)
    if "date" in df.columns:
        df = df.drop(columns=["date"])
    df.columns = df.columns.str.strip() 

    correlations = df.corr(method='pearson')[target_column].sort_values(ascending=False) # https://wikidocs.net/157461
    #피어슨 상관관계. (-1~1 코시-슈바르츠)
    # 공분산/(표준편차^2)
    print("Feature Correlations with Target Label:")
    print(correlations)
    #https://dd0za-1004.tistory.com/46 0.3 이상이면 뚜렷한 상관관계
    return correlations
# 파일 경로
train_file = "training.csv"

correlations = calculate_correlations(train_file, target_column="label")
