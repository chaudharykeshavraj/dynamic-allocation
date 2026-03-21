import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
import matplotlib.dates as mdates

# Set style for research paper quality
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['legend.fontsize'] = 10
plt.rcParams['figure.dpi'] = 150
plt.rcParams['savefig.dpi'] = 300

# Read the CSV file
df = pd.read_csv('allocate_vs_demand_vs_enforced 2.csv')
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Calculate totals per interval
interval_data = df.groupby('timestamp').agg({
    'down_bytes_per_sec': 'sum',      # Total Demand Down
    'up_bytes_per_sec': 'sum',        # Total Demand Up
    'allocated_bytes_download': 'sum', # Total Allocated Down
    'allocated_bytes_upload': 'sum',   # Total Allocated Up
    'enforced_down_bps': 'sum',        # Total Enforced Down
    'enforced_up_bps': 'sum'           # Total Enforced Up
}).reset_index()

# Convert to Mbps
interval_data['demand_down_mbps'] = interval_data['down_bytes_per_sec'] * 8 / 1_000_000
interval_data['demand_up_mbps'] = interval_data['up_bytes_per_sec'] * 8 / 1_000_000
interval_data['allocated_down_mbps'] = interval_data['allocated_bytes_download'] * 8 / 1_000_000
interval_data['allocated_up_mbps'] = interval_data['allocated_bytes_upload'] * 8 / 1_000_000
interval_data['enforced_down_mbps'] = interval_data['enforced_down_bps'] * 8 / 1_000_000
interval_data['enforced_up_mbps'] = interval_data['enforced_up_bps'] * 8 / 1_000_000

# Calculate total bandwidth (down + up)
interval_data['demand_total_mbps'] = interval_data['demand_down_mbps'] + interval_data['demand_up_mbps']
interval_data['allocated_total_mbps'] = interval_data['allocated_down_mbps'] + interval_data['allocated_up_mbps']
interval_data['enforced_total_mbps'] = interval_data['enforced_down_mbps'] + interval_data['enforced_up_mbps']

# Create figure
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Dynamic Bandwidth Allocation System Performance', fontsize=16, fontweight='bold', y=0.98)

# Color scheme
colors = {
    'demand': '#2E86AB',      # Blue
    'allocated': '#A23B72',   # Purple
    'enforced': '#F18F01',    # Orange
    'download': '#2E86AB',
    'upload': '#F18F01'
}

# ============================================================================
# Plot 1: Total Bandwidth (Download + Upload Combined)
# ============================================================================
ax1 = axes[0, 0]

ax1.fill_between(interval_data['timestamp'], 0, interval_data['demand_total_mbps'], 
                 alpha=0.3, color=colors['demand'], label='Demand')
ax1.plot(interval_data['timestamp'], interval_data['demand_total_mbps'], 
         color=colors['demand'], linewidth=1.5, alpha=0.8)

ax1.plot(interval_data['timestamp'], interval_data['allocated_total_mbps'], 
         color=colors['allocated'], linewidth=2, linestyle='--', label='Allocated')
ax1.plot(interval_data['timestamp'], interval_data['enforced_total_mbps'], 
         color=colors['enforced'], linewidth=2, marker='o', markersize=3, 
         linestyle='-', label='Enforced')

ax1.set_ylabel('Bandwidth (Mbps)', fontsize=12)
ax1.set_title('(a) Total Bandwidth (Downlink + Uplink)', fontsize=12, fontweight='bold')
ax1.legend(loc='upper right', framealpha=0.9)
ax1.grid(True, alpha=0.3)
ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax1.tick_params(axis='x', rotation=45)

# ============================================================================
# Plot 2: Download Bandwidth (Separate)
# ============================================================================
ax2 = axes[0, 1]

ax2.fill_between(interval_data['timestamp'], 0, interval_data['demand_down_mbps'], 
                 alpha=0.3, color=colors['download'], label='Demand')
ax2.plot(interval_data['timestamp'], interval_data['demand_down_mbps'], 
         color=colors['download'], linewidth=1.5, alpha=0.8)

ax2.plot(interval_data['timestamp'], interval_data['allocated_down_mbps'], 
         color=colors['allocated'], linewidth=2, linestyle='--', label='Allocated')
ax2.plot(interval_data['timestamp'], interval_data['enforced_down_mbps'], 
         color=colors['enforced'], linewidth=2, marker='s', markersize=3, 
         linestyle='-', label='Enforced')

ax2.set_ylabel('Bandwidth (Mbps)', fontsize=12)
ax2.set_title('(b) Downlink Bandwidth', fontsize=12, fontweight='bold')
ax2.legend(loc='upper right', framealpha=0.9)
ax2.grid(True, alpha=0.3)
ax2.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax2.tick_params(axis='x', rotation=45)

# ============================================================================
# Plot 3: Upload Bandwidth (Separate)
# ============================================================================
ax3 = axes[1, 0]

ax3.fill_between(interval_data['timestamp'], 0, interval_data['demand_up_mbps'], 
                 alpha=0.3, color=colors['upload'], label='Demand')
ax3.plot(interval_data['timestamp'], interval_data['demand_up_mbps'], 
         color=colors['upload'], linewidth=1.5, alpha=0.8)

ax3.plot(interval_data['timestamp'], interval_data['allocated_up_mbps'], 
         color=colors['allocated'], linewidth=2, linestyle='--', label='Allocated')
ax3.plot(interval_data['timestamp'], interval_data['enforced_up_mbps'], 
         color=colors['enforced'], linewidth=2, marker='^', markersize=3, 
         linestyle='-', label='Enforced')

ax3.set_ylabel('Bandwidth (Mbps)', fontsize=12)
ax3.set_xlabel('Time', fontsize=12)
ax3.set_title('(c) Uplink Bandwidth', fontsize=12, fontweight='bold')
ax3.legend(loc='upper right', framealpha=0.9)
ax3.grid(True, alpha=0.3)
ax3.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax3.tick_params(axis='x', rotation=45)

# ============================================================================
# Plot 4: Allocation Accuracy (Enforced/Allocated Ratio)
# ============================================================================
ax4 = axes[1, 1]

accuracy_down = (interval_data['enforced_down_mbps'] / (interval_data['allocated_down_mbps'] + 0.01)) * 100
accuracy_up = (interval_data['enforced_up_mbps'] / (interval_data['allocated_up_mbps'] + 0.01)) * 100
accuracy_total = (interval_data['enforced_total_mbps'] / (interval_data['allocated_total_mbps'] + 0.01)) * 100

# Clip for better visualization
accuracy_down = np.clip(accuracy_down, 0, 200)
accuracy_up = np.clip(accuracy_up, 0, 200)
accuracy_total = np.clip(accuracy_total, 0, 200)

ax4.axhline(y=100, color='green', linestyle='--', linewidth=1.5, alpha=0.7, label='Ideal (100%)')
ax4.fill_between(interval_data['timestamp'], 80, 120, alpha=0.2, color='green', label='Acceptable Range (80-120%)')

ax4.plot(interval_data['timestamp'], accuracy_total, color='#2E86AB', linewidth=2, 
         marker='o', markersize=4, label='Total')
ax4.plot(interval_data['timestamp'], accuracy_down, color='#A23B72', linewidth=1.5, 
         linestyle='--', alpha=0.7, label='Download')
ax4.plot(interval_data['timestamp'], accuracy_up, color='#F18F01', linewidth=1.5, 
         linestyle='--', alpha=0.7, label='Upload')

ax4.set_ylabel('Accuracy (%)', fontsize=12)
ax4.set_xlabel('Time', fontsize=12)
ax4.set_title('(d) Allocation Accuracy (Enforced / Allocated × 100%)', fontsize=12, fontweight='bold')
ax4.legend(loc='upper right', framealpha=0.9)
ax4.grid(True, alpha=0.3)
ax4.set_ylim(0, 200)
ax4.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax4.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('system_bandwidth_overview.png', dpi=300, bbox_inches='tight', 
            facecolor='white', edgecolor='none')
plt.show()

# ============================================================================
# Print Summary Statistics
# ============================================================================
print("\n" + "="*80)
print("SYSTEM PERFORMANCE SUMMARY")
print("="*80)

print("\n📊 BANDWIDTH STATISTICS (Mbps):")
print(f"{'Metric':<20} {'Demand':>10} {'Allocated':>12} {'Enforced':>12} {'Efficiency':>12}")
print("-"*70)
print(f"{'Total (Down+Up)':<20} {interval_data['demand_total_mbps'].mean():>10.2f} "
      f"{interval_data['allocated_total_mbps'].mean():>12.2f} "
      f"{interval_data['enforced_total_mbps'].mean():>12.2f} "
      f"{accuracy_total.mean():>11.1f}%")
print(f"{'Downlink Only':<20} {interval_data['demand_down_mbps'].mean():>10.2f} "
      f"{interval_data['allocated_down_mbps'].mean():>12.2f} "
      f"{interval_data['enforced_down_mbps'].mean():>12.2f} "
      f"{accuracy_down.mean():>11.1f}%")
print(f"{'Uplink Only':<20} {interval_data['demand_up_mbps'].mean():>10.2f} "
      f"{interval_data['allocated_up_mbps'].mean():>12.2f} "
      f"{interval_data['enforced_up_mbps'].mean():>12.2f} "
      f"{accuracy_up.mean():>11.1f}%")

print("\n📈 CORRELATION ANALYSIS:")
corr_alloc_enforced_down = interval_data['allocated_down_mbps'].corr(interval_data['enforced_down_mbps'])
corr_alloc_enforced_up = interval_data['allocated_up_mbps'].corr(interval_data['enforced_up_mbps'])
corr_demand_alloc_down = interval_data['demand_down_mbps'].corr(interval_data['allocated_down_mbps'])
print(f"  Allocated vs Enforced (Down):  r = {corr_alloc_enforced_down:.4f}")
print(f"  Allocated vs Enforced (Up):    r = {corr_alloc_enforced_up:.4f}")
print(f"  Demand vs Allocated (Down):    r = {corr_demand_alloc_down:.4f}")

print("\n🎯 SYSTEM METRICS:")
print(f"  Average Utilization: {(interval_data['enforced_total_mbps'].mean() / (interval_data['demand_total_mbps'].mean() + 0.01) * 100):.1f}%")
print(f"  Peak Demand: {interval_data['demand_total_mbps'].max():.2f} Mbps")
print(f"  Peak Enforced: {interval_data['enforced_total_mbps'].max():.2f} Mbps")
print(f"  Allocation Error (MAE): {(accuracy_total - 100).abs().mean():.1f}%")

print("\n✅ SYSTEM HEALTH SCORE:")
efficiency_score = accuracy_total.mean()
if efficiency_score >= 95:
    grade = "🟢 EXCELLENT"
elif efficiency_score >= 85:
    grade = "🟡 GOOD"
elif efficiency_score >= 70:
    grade = "🟠 FAIR"
else:
    grade = "🔴 POOR"
print(f"  {grade} - {efficiency_score:.1f}% average allocation accuracy")

print("\n" + "="*80)
print("Plot saved as: system_bandwidth_overview.png")
print("="*80)