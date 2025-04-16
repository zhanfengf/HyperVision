import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.decomposition import PCA
import argparse

# Command-line argument parsing
parser = argparse.ArgumentParser(description="Visualize clustering results from CSV")
parser.add_argument("input_csv", type=str, help="Path to the input CSV file")
parser.add_argument("output_image", type=str, help="Path to save the output image")
args = parser.parse_args()

# Load data from CSV
df = pd.read_csv(args.input_csv)

# Select features and perform PCA
features = [col for col in df.columns if "Feature_" in col]
X = df[features]  # Feature matrix
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X)  # Reduce dimensions to 2D

# Add PCA results to the dataframe
df["PCA_1"] = X_pca[:, 0]
df["PCA_2"] = X_pca[:, 1]

# Plot settings
plt.figure(figsize=(10, 6))
sns.set(style="whitegrid")

# Separate data based on Loss for different markers
low_loss = df[df["Loss"] < 10]
high_loss = df[df["Loss"] >= 10]

# Scatter plot: Dots for low loss
plt.scatter(low_loss["PCA_1"], low_loss["PCA_2"], c=low_loss["ClusterID"], cmap="viridis", label="Low Loss (<10)", alpha=0.7, marker="o")

# Scatter plot: Crosses for high loss
plt.scatter(high_loss["PCA_1"], high_loss["PCA_2"], color="red", label="High Loss (≥10)", alpha=0.7, marker="x")
# Count the number of high-loss points
num_high_loss = len(high_loss)
print(f"Number of high-loss points (Loss >= 10): {num_high_loss}")

# Add labels and legend
plt.title("PCA-Based Cluster Visualization with Loss Indicators")
plt.xlabel("Principal Component 1")
plt.ylabel("Principal Component 2")
plt.colorbar(label="Cluster ID")
plt.legend()

# Save the plot as an image
plt.savefig(args.output_image)
print(f"Visualization saved to {args.output_image}")
