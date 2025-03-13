
input_file_path = '/home/yangting/Documents/Ble_Test/result/log_file/Cypress/test_all.txt'
output_file_path = '/home/yangting/Documents/Ble_Test/result/log_file/Cypress/test_analysis.txt'


with open(input_file_path, 'r') as infile:
    lines = infile.readlines()

# Add line numbers
numbered_lines = [f"{idx + 1}: {line}" for idx, line in enumerate(lines)]

# Save to the same output file
with open(input_file_path, 'w') as outfile:
    outfile.writelines(numbered_lines)




# Define the target patterns
pre_end = '-----------------Pre End-----------------'
post_start = '-----------------Post Start-----------------'
rx_btle = 'RX <--- BTLE / BTLE_DATA '
fail = 'TX ---> BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Failed'

# Open the input file and filter the lines
with open(input_file_path, 'r') as infile, open(output_file_path, 'w') as outfile:
    for line in infile:
        if pre_end in line or post_start in line or rx_btle in line or fail in line:
            outfile.write(line)