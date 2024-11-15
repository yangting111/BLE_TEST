#!/bin/bash

# Check if an argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <dot file>"
    exit 1
fi

# Get the input file name
input_file="$1"

# Check if the input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: File $input_file does not exist"
    exit 1
fi

# Get the file name and extension
filename=$(basename -- "$input_file")
extension="${filename##*.}"
filename="${filename%.*}"

# Check if the file extension is dot
if [ "$extension" != "dot" ]; then
    echo "Error: File $input_file is not a dot file"
    exit 1
fi

# Generate the PDF file
output_file="${filename}.pdf"
dot -Tpdf "$input_file" -o "$output_file"

# Check if the conversion was successful
if [ $? -eq 0 ]; then
    echo "Conversion successful: $input_file -> $output_file"
else
    echo "Conversion failed"
    exit 1
fi
