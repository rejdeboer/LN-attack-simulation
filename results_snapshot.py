import csv
import ast
import nested_dict as nd
import matplotlib.pyplot as plt
import numpy as np
import json
import seaborn as sns
import os
import networkx as nx
import populate_graph as pg

#file = "results/less-hops-results-ad3f8ed0-50be-424c-9f81-5cd7f43b9640.json"
directory = 'results'

# Open the results file and transfer the in an array
results = []
for filename in os.listdir(directory):
    with open(directory + '/' + filename, 'r') as json_file:
        results_json = json.load(json_file)
    results.append(results_json)

path = []

# Efficiency metrics
total_cost_ratio = 0
total_delay = 0
failed = 0

# False positives old
source_false_positives_old = 0
destination_false_positives_old = 0
pairwise_source_false_positives_old = 0
num_destinations_old = 0
num_sources_old = 0
correct_singular_dest_old = 0
correct_singular_pairwise_source_old = 0

# False positives
source_false_positives = 0
destination_false_positives = 0
pairwise_source_false_positives = 0
num_destinations = 0
num_sources = 0
correct_singular_dest = 0
correct_singular_pairwise_source = 0

# Number of Transactions
num_transactions = 0

# Number of transactions attacked
num_attacked = 0

# Total number of attack instances
num_attacks = 0

# Array storing the number of recipients for each attack instance, followed by those that that had phase I completed and not respectively
dest_count_old = []
dest_count_comp_old = []
dest_count_incomp_old = []

# Arrays storing the number of senders for each attack instance, followed by those that that had phase I completed and not respectively
source_count_old = []
source_count_comp_old = []
source_count_incomp_old = []

# Arrays storing the distances of the recipient and the sender from the adversary respectively
dist_dest_old = []
dist_source_old = []

# Array storing the number of recipients for each attack instance, followed by those that that had phase I completed and not respectively
dest_count = []
dest_count_comp = []
dest_count_incomp = []

# Arrays storing the number of senders for each attack instance, followed by those that that had phase I completed and not respectively
source_count = []
source_count_comp = []
source_count_incomp = []

# Arrays storing the distances of the recipient and the sender from the adversary respectively
dist_dest = []
dist_source = []

# Number of attack instances in which the sender and recipient pair was successfully found
pair_found = 0
rec_found = 0

# Number of attack instances in which the sender and recipient pair was successfully found OLD
pair_found_old = 0
rec_found_old = 0

# Number of attack instances that completed phase I
num_comp_old = 0

# Number of attack instances that completed phase I
num_comp = 0

num_hops = 0

# Number of attack instances for which the size of the recipient set was 1 and similarly for the sender OLD
sing_dest_old = 0
sing_source_old = 0

# Number of attack instances having both the sender and recipient sets singular OLD
sing_all_old = 0

# Number of attack instances having atleast one of the sender and recipient sets singular OLD
sing_any_old = 0

# Number of attack instances for which the size of the recipient set was 1 and similarly for the sender
sing_dest = 0
sing_source = 0

# Number of attack instances having both the sender and recipient sets singular
sing_all = 0

# Number of attack instances having atleast one of the sender and recipient sets singular
sing_any = 0
ads = [2634, 8075, 5347, 1083, 5093,4326, 4126, 2836, 5361, 10572,5389, 3599, 9819, 4828, 3474, 8808, 93, 9530, 9515, 2163]


# Dictionary for storing the number of attack instances of each adversary
ad_attacks = {}
for ad in ads:
    ad_attacks[ad] = 0

# Go over the results and update each of the above variables for each attack instance
for i in results:
    for k in i:
        if k["path"] != path:
            path = k["path"]
            num_hops += len(path) - 2
            num_transactions += 1
            total_cost_ratio += (k["cost"] - k["amount"]) / k["cost"]
            total_delay += k["delay"]
            if not k["success"]:
                failed += 1
            if k["attacked"] > 0:
                num_attacked += 1
                if "anon_sets_old" in k:
                    anon_sets = k["anon_sets_old"]
                    for ad in anon_sets:
                        false_positive = True
                        num = -1
                        for adv in ad:
                            sources = []
                            num += 1
                            for dest in ad[adv]:
                                for rec in dest:
                                    source_is_false_pairwise = False
                                    num_destinations_old += 1
                                    if str(k["recipient"]) == rec:
                                        rec_found_old += 1
                                        false_positive = False
                                        source_is_false_pairwise = True
                                    for tech in dest[rec]:

                                        if k["sender"] not in dest[rec][tech]:
                                            source_false_positives_old += 1
                                        if str(k["recipient"]) == rec:
                                            if k["sender"] in dest[rec][tech]:
                                                pair_found_old += 1
                                                source_is_false_pairwise = False
                                        num_sources_old += len(dest[rec][tech])
                                        for s in dest[rec][tech]:
                                            sources.append(s)
                                    if source_is_false_pairwise:
                                        pairwise_source_false_positives_old += 1
                            if len(set(sources)) > 0:
                                ind = k["path"].index(int(adv))
                                dist_dest_old.append(len(k["path"]) - 1 - ind)
                                dist_source_old.append(ind)
                                if (k["comp_attack"][num] == 1):
                                    dest_count_comp_old.append(len(ad[adv]))
                                    num_comp_old += 1
                                else:
                                    dest_count_incomp_old.append(len(ad[adv]))
                                dest_count_old.append(len(ad[adv]))
                                if (len(ad[adv]) == 1):
                                    if not false_positive:
                                        correct_singular_dest_old += 1
                                    sing_dest_old += 1
                                if (k["comp_attack"][num] == 1):
                                    source_count_comp_old.append(len(set(sources)))
                                else:
                                    source_count_incomp_old.append(len(set(sources)))
                                source_count_old.append(len(set(sources)))
                                if (len(set(sources)) == 1):
                                    if int(k["sender"]) in sources:
                                        correct_singular_pairwise_source_old += 1
                                    sing_source_old += 1
                                if (len(ad[adv]) == 1) or (len(set(sources)) == 1):
                                    sing_any_old += 1
                                if (len(ad[adv]) == 1) and (len(set(sources)) == 1):
                                    sing_all_old += 1
                        if false_positive:
                            destination_false_positives_old += 1
                anon_sets = k["anon_sets"]
                for ad in anon_sets:
                    num_attacks += 1
                    false_positive = True
                    num = -1
                    for adv in ad:
                        sources = []
                        ad_attacks[int(adv)] += 1
                        num += 1
                        for dest in ad[adv]:
                            for rec in dest:
                                source_is_false_pairwise = False
                                num_destinations += 1
                                if str(k["recipient"]) == rec:
                                    false_positive = False
                                    source_is_false_pairwise = True
                                    rec_found += 1
                                for tech in dest[rec]:
                                    if k["sender"] not in dest[rec][tech]:
                                        source_false_positives += 1
                                    if str(k["recipient"]) == rec:
                                        if k["sender"] in dest[rec][tech]:
                                            pair_found += 1
                                            source_is_false_pairwise = False
                                    num_sources += len(dest[rec][tech])
                                    for s in dest[rec][tech]:
                                        sources.append(s)
                                if source_is_false_pairwise:
                                    pairwise_source_false_positives += 1
                        if len(set(sources)) > 0:
                            ind = k["path"].index(int(adv))
                            dist_dest.append(len(k["path"]) - 1 - ind)
                            dist_source.append(ind)
                            if (k["comp_attack"][num] == 1):
                                dest_count_comp.append(len(ad[adv]))
                                num_comp += 1
                            else:
                                dest_count_incomp.append(len(ad[adv]))
                            dest_count.append(len(ad[adv]))
                            if (len(ad[adv]) == 1):
                                if not false_positive:
                                    correct_singular_dest += 1
                                sing_dest += 1
                            if (k["comp_attack"][num] == 1):
                                source_count_comp.append(len(set(sources)))
                            else:
                                source_count_incomp.append(len(set(sources)))
                            source_count.append(len(set(sources)))
                            if (len(set(sources)) == 1):
                                if int(k["sender"]) in sources:
                                    correct_singular_pairwise_source += 1
                                sing_source += 1
                            if (len(ad[adv]) == 1) or (len(set(sources)) == 1):
                                sing_any += 1
                            if (len(ad[adv]) == 1) and (len(set(sources)) == 1):
                                sing_all += 1
                    if false_positive:
                        destination_false_positives += 1


# Print the metrics
def perc(num):
    return round(num * 100, 2)


print('GENERAL METRICS')
print(f'Transactions: {num_transactions}')
print(f'Transactions attacked: {num_attacked}')
print(f'Attacks: {num_attacks}')
cost_ratio = total_cost_ratio / num_transactions if num_transactions != 0 else 0
print(f'Average transaction cost ratio per transaction: {cost_ratio} ({perc(cost_ratio)}%)')
print(f'Average delay per transaction: {total_delay / num_transactions}')
print(f'Average amount of hops: {num_hops / num_transactions}')
attack_transaction_ratio = num_attacked / num_transactions if num_transactions != 0 else 0
attack_attacked_ratio = num_attacks / num_attacked if num_attacked != 0 else 0
print(f'Attacked/Transactions ratio: {attack_transaction_ratio} ({perc(attack_transaction_ratio)}%)')
print(f'Attacks/Attacked ratio: {attack_attacked_ratio} ({perc(attack_attacked_ratio)}%)')
failed_ratio = failed / num_transactions if num_transactions != 0 else 0
print(f'Failed transaction ratio: {failed_ratio} ({perc(failed_ratio)}%)')

print('OLD ATTACK')
print(f'Pairs found: {pair_found_old}')
avg_destinations_found = num_destinations_old / num_attacks if num_attacks != 0 else 0
avg_sources_found = num_sources_old / num_destinations_old if num_destinations_old != 0 else 0
print(f'Average sources per set: {avg_sources_found}')
print(f'Average destinations per set: {avg_destinations_found}')
# print(f'Sources found per attack: {source_count_old}')
# print(f'Destinations found per attack: {dest_count_old}')
print('Correlation destination to distance\n', np.corrcoef(dest_count_old, dist_dest_old))
print('Correlation source to distance\n', np.corrcoef(source_count_old, dist_source_old))

destination_false_positive_ratio = destination_false_positives_old / num_attacks if num_attacks != 0 else 0
source_false_positive_ratio = source_false_positives_old / num_destinations_old if num_destinations_old != 0 else 0
pairwise_source_false_positive_ratio = pairwise_source_false_positives_old / rec_found_old if rec_found_old != 0 else 0
sing_source_ratio = correct_singular_pairwise_source_old / num_attacks if num_attacks != 0 else 0
sing_dest_ratio = correct_singular_dest_old / num_attacks if num_attacks != 0 else 0
correct_sing_dest_ratio = correct_singular_dest_old / sing_dest_old if sing_dest_old != 0 else 0
sing_any_ratio = sing_any_old / num_attacks if num_attacks != 0 else 0
sing_all_ratio = sing_all_old / num_attacks if num_attacks != 0 else 0
complete_one_attack_ratio = num_comp_old / num_attacks if num_attacks != 0 else 0
print(f'Correct singular sources ratio: {sing_source_ratio} ({perc(sing_source_ratio)}%)')
print(f'Correct singular destination ratio: {sing_dest_ratio} ({perc(sing_dest_ratio)}%)')
print(
    f'Correct singular destination ratio (sanity check): {correct_sing_dest_ratio} ({perc(correct_sing_dest_ratio)}%)')
print(f'Singular source or destination ratio: {sing_any_ratio} ({perc(sing_any_ratio)}%)')
print(f'Both Singular ratio: {sing_all_ratio} ({perc(sing_all_ratio)}%)')
print(f'Complete I phase ratio: {complete_one_attack_ratio} ({perc(complete_one_attack_ratio)}%)')
print(
    f'Destination false positive ratio: {destination_false_positive_ratio} ({perc(destination_false_positive_ratio)}%)')
print(f'Source false positive ratio: {source_false_positive_ratio} ({perc(source_false_positive_ratio)}%)')
print(
    f'Pairwise source false positive ratio: {pairwise_source_false_positive_ratio} ({perc(pairwise_source_false_positive_ratio)}%)')

# Print the metrics
print('NEW ATTACK')
print(f'Pairs found: {pair_found}')
avg_destinations_found = num_destinations / num_attacks if num_attacks != 0 else 0
avg_sources_found = num_sources / num_destinations if num_destinations != 0 else 0
print(f'Average sources per set: {avg_sources_found}')
print(f'Average destinations per set: {avg_destinations_found}')
# print(f'Sources found per attack: {source_count}')
# print(f'Destinations found per attack: {dest_count}')
print('Correlation destination to distance\n', np.corrcoef(dest_count, dist_dest))
print('Correlation source to distance\n', np.corrcoef(source_count, dist_source))

destination_false_positive_ratio = destination_false_positives / num_attacks if num_attacks != 0 else 0
source_false_positive_ratio = source_false_positives / num_destinations if num_destinations != 0 else 0
pairwise_source_false_positive_ratio = pairwise_source_false_positives / rec_found if rec_found != 0 else 0
sing_source_ratio = correct_singular_pairwise_source / num_attacks if num_attacks != 0 else 0
sing_dest_ratio = correct_singular_dest / num_attacks if num_attacks != 0 else 0
correct_sing_dest_ratio = correct_singular_dest / sing_dest if sing_dest != 0 else 0
sing_any_ratio = sing_any / num_attacks if num_attacks != 0 else 0
sing_all_ratio = sing_all / num_attacks if num_attacks != 0 else 0
complete_one_attack_ratio = num_comp / num_attacks if num_attacks != 0 else 0
print(f'Correct singular sources ratio: {sing_source_ratio} ({perc(sing_source_ratio)}%)')
print(f'Correct singular destination ratio: {sing_dest_ratio} ({perc(sing_dest_ratio)}%)')
print(
    f'Correct singular destination ratio (sanity check): {correct_sing_dest_ratio} ({perc(correct_sing_dest_ratio)}%)')
print(f'Singular source or destination ratio: {sing_any_ratio} ({perc(sing_any_ratio)}%)')
print(f'Both Singular ratio: {sing_all_ratio} ({perc(sing_all_ratio)}%)')
print(f'Complete I phase ratio: {complete_one_attack_ratio} ({perc(complete_one_attack_ratio)}%)')
print(
    f'Destination false positive ratio: {destination_false_positive_ratio} ({perc(destination_false_positive_ratio)}%)')
print(f'Source false positive ratio: {source_false_positive_ratio} ({perc(source_false_positive_ratio)}%)')
print(
    f'Pairwise source false positive ratio: {pairwise_source_false_positive_ratio} ({perc(pairwise_source_false_positive_ratio)}%)')

# Plot the sender and recipient anonymity sets respectively
#plot1 = sns.ecdfplot(data=dest_count_comp, legend='Phase I complete', marker='|', linewidth=1.5, linestyle=':')
#plot2 = sns.ecdfplot(data=dest_count_incomp, legend='Phase I incomplete', marker='|', linewidth=1.5, linestyle=':')
#plot1.set(xscale='log')
#plot2.set(xscale='log')
#plt.legend(('Phase I complete', 'Phase I incomplete'), scatterpoints=1, loc='lower right', ncol=1, fontsize=16)
#plt.xlabel("Size of anonymity set")
#plt.ylabel("CDF")
#plt.show()

#plot1 = sns.ecdfplot(data=source_count_comp, legend='Phase I complete', marker='|', linewidth=1.5, linestyle=':')
#plot2 = sns.ecdfplot(data=source_count_incomp, legend='Phase I incomplete', marker='|', linewidth=1.5, linestyle=':')
#plot1.set(xscale='log')
#plot2.set(xscale='log')
#plt.legend(('Phase I complete', 'Phase I incomplete'), scatterpoints=1, loc='lower right', ncol=1, fontsize=16)
#plt.xlabel("Size of anonymity set")
#plt.ylabel("CDF")
#plt.show()
