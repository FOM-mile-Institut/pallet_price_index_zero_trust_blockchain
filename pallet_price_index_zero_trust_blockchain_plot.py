''' 
This script reads a JSON file containing blockchain data, extracts the price statistics,
and generates a line chart to visualize the average, median, and weighted average prices over time.
It uses the matplotlib library for plotting.
The script assumes the JSON file is structured correctly and contains the necessary fields.

'''

import json
import matplotlib.pyplot as plt
from datetime import datetime
from pallet_price_index_zero_trust_blockchain import Blockchain 

# Read blockchain.json
try:
    with open('blockchain_20250425_154307.json', 'r') as file:
        blockchain = json.load(file)
except FileNotFoundError:
    print("Error: blockchain.json not found")
    exit(1)
except json.JSONDecodeError:
    print("Error: Invalid JSON structure in blockchain.json")
    exit(1)

# Extract stats from blocks (skip genesis block with stats=None)
stats_data = [
    block['stats'] for block in blockchain
    if block['stats'] is not None
]

# Sort by year_week to ensure chronological order
stats_data.sort(key=lambda x: x['year_week'])

# Prepare data for plotting
weeks = [data['year_week'] for data in stats_data]
avg_prices = [data['avg_price_per_day'] for data in stats_data]
median_prices = [data['median_price'] for data in stats_data]
weighted_avg_prices = [data['weighted_avg_price'] for data in stats_data]

# Create the plot
plt.figure(figsize=(10, 6))
plt.plot(weeks, avg_prices, marker='o', label='Average Price per Day', color='blue')
plt.plot(weeks, median_prices, marker='s', label='Median Price', color='green')
plt.plot(weeks, weighted_avg_prices, marker='^', label='Weighted Average Price', color='red')

# Customize the chart
plt.title('Pallet Price Index Over Time', fontsize=14)
plt.xlabel('Week (Year-Week)', fontsize=12)
plt.ylabel('Price (EUR)', fontsize=12)
plt.grid(True)
plt.legend()
plt.xticks(rotation=45, ha='right')
plt.tight_layout()

# Save the plot to a file
plt.savefig('price_index_chart.png')