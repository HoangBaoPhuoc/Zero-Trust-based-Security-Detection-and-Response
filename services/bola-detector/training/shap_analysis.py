# services/bola-detector/training/shap_analysis.py
import shap


def explain(model, X_sample):
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    shap.summary_plot(shap_values, X_sample, show=False)
    import matplotlib.pyplot as plt
    plt.savefig("../model/shap_summary.png", bbox_inches="tight")
    # kiểm tra riêng: đặc trưng nào liên quan cross-cloud call không được đứng
    # top-1 áp đảo — nếu có, nghi ngờ model học bố trí thí nghiệm thay vì bản
    # chất tấn công (đúng cảnh báo trong đề cương)
    return shap_values
