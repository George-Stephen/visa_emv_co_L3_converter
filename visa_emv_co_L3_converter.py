import re
from lxml import etree as ET
from datetime import datetime, timezone
import binascii
import os
import glob

# Fallback EBCDIC to ASCII mapping (simplified for common characters)
EBCDIC_TO_ASCII = {
    0xF0: '0', 0xF1: '1', 0xF2: '2', 0xF3: '3', 0xF4: '4',
    0xF5: '5', 0xF6: '6', 0xF7: '7', 0xF8: '8', 0xF9: '9',
    0xC1: 'A', 0xC2: 'B', 0xC3: 'C', 0xC4: 'D', 0xC5: 'E',
    0xC6: 'F', 0xC7: 'G', 0xC8: 'H', 0xC9: 'I', 0xD1: 'J',
    0xD2: 'K', 0xD3: 'L', 0xD4: 'M', 0xD5: 'N', 0xD6: 'O',
    0xD7: 'P', 0xD8: 'Q', 0xD9: 'R', 0xE2: 'S', 0xE3: 'T',
    0xE4: 'U', 0xE5: 'V', 0xE6: 'W', 0xE7: 'X', 0xE8: 'Y',
    0xE9: 'Z', 0x40: ' '
}

def ascii_to_ebcdic(text):
    """Convert ASCII text to EBCDIC hex string."""
    ebcdic_map = {v: k for k, v in EBCDIC_TO_ASCII.items()}
    return ''.join(f'{ebcdic_map.get(c, 0x40):02X}' for c in text)

def ebcdic_to_ascii(hex_str):
    """Convert EBCDIC hex string to ASCII."""
    try:
        hex_bytes = bytes.fromhex(hex_str)
        return ''.join(EBCDIC_TO_ASCII.get(b, '?') for b in hex_bytes)
    except ValueError:
        return hex_str  # Return as-is if invalid hex

def parse_inovant_log(log_data):
    """
    Parse Inovant VTS log to extract fields for each message.
    Returns a list of message dictionaries with MTI, class, and fields.
    """
    messages = []
    raw_messages = re.split(r'(?=ISO\^)', log_data.strip())
    raw_messages = [msg.strip() for msg in raw_messages if msg.strip()]

    for msg_block in raw_messages:
        # Extract MTI
        mti_match = re.search(r'\b(01[0-1]0|08[0-1]0)\b', msg_block)
        if not mti_match:
            mti_match = re.search(r'sID:MTI\s+sNAME:[^~]+\s+sDATA:(01[0-1]0|08[0-1]0)', msg_block)
            if not mti_match:
                print(f"Skipping message block: No valid MTI found in {msg_block[:50]}...")
                continue
        mti = mti_match.group(1)
        
        class_type = 'Request' if mti in ('0100', '0800') else 'Response'
        source, destination = ("N/A", "TestIssuer|Network") if class_type == "Request" else ("TestIssuer|Network", "N/A")

        # Extract all fields
        field_pattern = r'~sID:([^ ~]+)\s+sNAME:([^~]+?)\s+sDATA:([^~]*?)(?:\s+sACDATA:([^~]*))?(?=\s*(?:~|\^~|\s+~|$))'
        all_fields = re.findall(field_pattern, msg_block, re.DOTALL)

        # Debug: Log all extracted fields
        print(f"\nExtracted fields for MTI {mti} ({class_type}):")
        field_ids = []
        for fid, fname, fdata, facdata in all_fields:
            print(f"ID={fid}, Name={fname}, Data={fdata}, ACData={facdata or 'None'}")
            field_ids.append(fid)

        # Process fields: Exclude headers and empty bitmaps
        fields = []
        excluded_prefixes = ['H0', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H9', 'H10', 'H11', 'H12', 'MTI']
        
        for fid, fname, fdata, facdata in all_fields:
            if any(fid.startswith(prefix) for prefix in excluded_prefixes):
                continue
            if fid.endswith('BMP') and not fdata.strip() and not (facdata and facdata.strip()):
                continue
                
            field = {
                'id': fid.strip(),
                'name': fname.strip(),
                'value': fdata.strip() if fdata else '',
                'acdata': facdata.strip() if facdata else None
            }
            fields.append(field)

        # Group subfields (e.g., F3.1, F55.3) under their parent fields
        grouped_fields = []
        current_parent = None
        for field in fields:
            if '.' in field['id']:
                if current_parent:
                    current_parent.setdefault('subfields', []).append(field)
                continue
            if current_parent:
                grouped_fields.append(current_parent)
            current_parent = field
        if current_parent:
            grouped_fields.append(current_parent)

        message = {
            'mti': mti,
            'class': class_type,
            'source': source,
            'destination': destination,
            'fields': grouped_fields,
            'all_field_ids': field_ids
        }
        messages.append(message)

    return messages

def guess_field_type(fid):
    """
    Map field ID to ISO 8583 data type, handling subfields and EMV tags.
    """
    base_fid = fid.split('.')[0] if '.' in fid else fid
    field_types = {
        "F01": "b64", "F02": "N..19", "F03": "n6", "F04": "n12", "F05": "n12",
        "F06": "n12", "F07": "DateTime MMDDhhmmss", "F08": "n8", "F09": "n8", "F10": "n8",
        "F11": "n6", "F12": "DateTime hhmmss", "F13": "DateTime MMDD", "F14": "DateTime YYMM",
        "F15": "DateTime MMDD", "F16": "DateTime MMDD", "F17": "DateTime MMDD", "F18": "n4",
        "F19": "n3", "F20": "n3", "F21": "n3", "F22": "n3", "F23": "n3", "F24": "n3",
        "F25": "n2", "F26": "n2", "F27": "n1", "F28": "x+n8", "F29": "x+n8", "F30": "n24",
        "F31": "n24", "F32": "N..6", "F33": "LLVAR n..11", "F34": "LLVAR ans..28",
        "F35": "Z..37", "F36": "LLLVAR n..104", "F37": "ANS12", "F38": "ANS6",
        "F39": "an2", "F40": "an3", "F41": "ANS8", "F42": "ANS15", "F43": "ANS40",
        "F44": "ANS25", "F45": "LLVAR ans..76", "F46": "LLLVAR ans..999",
        "F47": "LLLVAR ans..999", "F48": "LLLVAR ans..999", "F49": "n3",
        "F50": "n3", "F51": "n3", "F52": "b64", "F53": "n16", "F54": "LLLVAR an..120",
        "F55": "B..255", "F56": "LLVAR ans..35", "F57": "LLLVAR ans..999",
        "F58": "LLLVAR ans..999", "F59": "LLLVAR ans..999", "F60": "ANS..999",
        "F61": "ANS..26", "F62": "B..999", "F63": "AN..50",
        "BMP": "b8"
    }
    if 'TAG' in fid:
        tag = fid.split('TAG.')[-1]
        tag_types = {
            '9F33': 'B3', '95': 'b5', '9F37': 'b4', '9F26': 'b8', '9F36': 'b2',
            '82': 'b2', '9C': 'b1', '9F1A': 'b2', '9A': 'B3', '9F02': 'b6',
            '5F2A': 'b2', '9F03': 'b6', '9F27': 'b1', '9F34': 'B3', '9F35': 'B1',
            '9F53': 'B1', '84': 'B..16', '9F09': 'B2', '9F41': 'B..4', '9F10': 'B..32'
        }
        return tag_types.get(tag, 'B..255')
    return field_types.get(base_fid, "AN..999")

def get_field_value_for_encoding(field, class_type):
    """Select value for binary encoding based on message type."""
    return field['acdata'] if class_type == "Request" and field['acdata'] else field['value']

def get_field_viewable_value(field, class_type):
    """Select value for display based on message type."""
    return field['acdata'] if class_type == "Request" and field['acdata'] else field['value']

def generate_emvco_l3_xml(messages):
    """
    Generate EMVCo L3 XML from parsed messages, matching the provided format.
    """
    root = ET.Element("EMVCoL3OnlineMessageFormat")

    # LogDetails
    log_details = ET.SubElement(root, "LogDetails")
    ET.SubElement(log_details, "Date-Time").text = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = ET.SubElement(log_details, "LoggingTool")
    ET.SubElement(tool, "ProductName").text = "Inovant VTS Simulator"
    ET.SubElement(tool, "ProductVersion").text = "1.0.0"
    ET.SubElement(log_details, "SchemaSelectionIndex").text = "1.1"
    ET.SubElement(log_details, "Reference").text = "EMVCo L3 Online Message Format"
    ET.SubElement(log_details, "L3OMLVersion").text = "1.1"

    # ConnectionList
    conn_list = ET.SubElement(root, "ConnectionList")
    conn = ET.SubElement(conn_list, "Connection", ID="TestIssuer|Network")
    proto = ET.SubElement(conn, "Protocol")
    ET.SubElement(proto, "FriendlyName").text = "VISA VSDC"
    ET.SubElement(proto, "SymbolicName").text = "VISAVSDC"
    ET.SubElement(proto, "VersionInfo").text = "1.0.0"
    tcpip = ET.SubElement(conn, "TCPIPParameters")
    ET.SubElement(tcpip, "Address").text = "."
    ET.SubElement(tcpip, "Port").text = "1234"
    ET.SubElement(tcpip, "Header").text = "prefixed:"
    ET.SubElement(tcpip, "Client").text = "false"
    ET.SubElement(tcpip, "Format").text = "EBCDIC"

    # OnlineMessageList
    online_msg_list = ET.SubElement(root, "OnlineMessageList")

    for msg in messages:
        mti = msg['mti']
        class_type = msg['class']
        fields = msg['fields']

        print(f"\nProcessing {class_type} message (MTI {mti}) with fields: {[f['id'] for f in fields]}")

        if not fields:
            print(f"Warning: No fields included for {class_type} message with MTI {mti}")
            continue

        online_msg = ET.SubElement(online_msg_list, "OnlineMessage",
                                   Class=class_type,
                                   Source=msg['source'],
                                   Destination=msg['destination'])

        # Generate RawData by concatenating field binary values
        raw_data = ""
        for field in fields:
            value = get_field_value_for_encoding(field, class_type)
            if value:
                if field['id'].startswith('BMP'):
                    # Convert bitmap to hex
                    try:
                        raw_data += value
                    except ValueError:
                        continue
                else:
                    raw_data += ascii_to_ebcdic(value)
        ET.SubElement(online_msg, "RawData").text = raw_data.upper()

        # MessageInfo
        msg_info = ET.SubElement(online_msg, "MessageInfo")
        ET.SubElement(msg_info, "PINValidated").text = "N/A"
        ET.SubElement(msg_info, "ARQCValidated").text = "true" if mti == "0100" else "N/A"
        ET.SubElement(msg_info, "MACValidated").text = "N/A"
        ET.SubElement(msg_info, "CVC3Track1Validated").text = "N/A"
        ET.SubElement(msg_info, "CVC3Track2Validated").text = "N/A"
        tool_comment = {
            "0800": "Group Sign On",
            "0810": "Group Sign On Response",
            "0100": "Authorization Request",
            "0110": "Authorization Request Response"
        }.get(mti, "Unknown")
        ET.SubElement(msg_info, "ToolComment").text = tool_comment
        ET.SubElement(msg_info, "Date-Time").text = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # FieldList
        field_list = ET.SubElement(online_msg, "FieldList")
        for field in fields:
            fid = field['id']
            fname = field['name']
            value_for_encoding = get_field_value_for_encoding(field, class_type)
            viewable_value = get_field_viewable_value(field, class_type)

            if not value_for_encoding and not viewable_value:
                print(f"Skipping field {fid}: No meaningful data (Encoding='{value_for_encoding}', Viewable='{viewable_value}')")
                continue

            # Adjust field ID for MTI and DE
            field_id = f"NET.{mti}.DE.-1" if fid == "BMP" and fname == "BitMap" else f"NET.{mti}.DE.{fid.replace('F', '').replace('.', '.SE.')}"
            if fid.startswith('F55.') and 'TAG' not in fid:
                field_id = f"NET.{mti}.DE.055.TAG.{fid.split('.')[-1]}"

            field_elem = ET.SubElement(field_list, "Field", ID=field_id)
            ET.SubElement(field_elem, "FriendlyName").text = fname
            ET.SubElement(field_elem, "FieldType").text = guess_field_type(fid)

            # Generate FieldBinary (EBCDIC hex)
            binary_value = ascii_to_ebcdic(value_for_encoding) if value_for_encoding else ""
            ET.SubElement(field_elem, "FieldBinary").text = binary_value.upper()
            ET.SubElement(field_elem, "FieldViewable").text = viewable_value or ""

            # Add EMV tag attributes for F55
            if fid.startswith('F55.') and 'TAG' not in fid:
                tag = fid.split('.')[-1]
                ET.SubElement(field_elem, "EMVData", Tag=tag, Name=fname, Format="V")

            # Add subfields if present
            if 'subfields' in field:
                subfield_list = ET.SubElement(field_elem, "FieldList")
                for subfield in field['subfields']:
                    sub_fid = subfield['id']
                    sub_fname = subfield['name']
                    sub_value = get_field_value_for_encoding(subfield, class_type)
                    sub_viewable = get_field_viewable_value(subfield, class_type)

                    subfield_id = f"NET.{mti}.DE.{fid}.SE.{sub_fid.split('.')[-1]}"
                    if sub_fid.startswith('F55.'):
                        subfield_id = f"NET.{mti}.DE.055.TAG.{sub_fid.split('.')[-1]}"

                    subfield_elem = ET.SubElement(subfield_list, "Field", ID=subfield_id)
                    ET.SubElement(subfield_elem, "FriendlyName").text = sub_fname
                    ET.SubElement(subfield_elem, "FieldType").text = guess_field_type(sub_fid)
                    ET.SubElement(subfield_elem, "FieldBinary").text = ascii_to_ebcdic(sub_value).upper() if sub_value else ""
                    ET.SubElement(subfield_elem, "FieldViewable").text = sub_viewable or ""

                    if sub_fid.startswith('F55.'):
                        tag = sub_fid.split('.')[-1]
                        ET.SubElement(subfield_elem, "EMVData", Tag=tag, Name=sub_fname, Format="V")

            print(f"Added field: ID={field_id}, Name={fname}, Encoding='{value_for_encoding}', Viewable='{viewable_value}'")

    # Add Signature
    sig = ET.SubElement(root, "Signature", xmlns="http://www.w3.org/2000/09/xmldsig#")
    signed_info = ET.SubElement(sig, "SignedInfo")
    ET.SubElement(signed_info, "CanonicalizationMethod",
                  Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    ET.SubElement(signed_info, "SignatureMethod",
                  Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    ref = ET.SubElement(signed_info, "Reference", URI="")
    transforms = ET.SubElement(ref, "Transforms")
    ET.SubElement(transforms, "Transform",
                  Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    ET.SubElement(ref, "DigestMethod", Algorithm="http://www.w3.org/2000/09/xmldsig#sha1")
    ET.SubElement(ref, "DigestValue").text = "DummyDigest=="
    ET.SubElement(sig, "SignatureValue").text = "DummySignatureValue"
    key_info = ET.SubElement(sig, "KeyInfo")
    ET.SubElement(key_info, "KeyName").text = "Inovant VTS Log Signature RSA Key 1"

    return root

def process_log_file(input_path, output_path):
    """
    Process a single log file and generate an XML file.
    """
    try:
        # Read the log file
        with open(input_path, 'r', encoding='utf-8') as f:
            log_data = f.read()
        
        if not log_data.strip():
            print(f"Warning: {input_path} is empty. Skipping.")
            return False

        # Parse log and generate XML
        print(f"\nProcessing file: {input_path}")
        parsed_messages = parse_inovant_log(log_data)
        
        if not parsed_messages:
            print(f"Warning: No valid messages found in {input_path}. Skipping.")
            return False

        # Print summary of fields
        for msg in parsed_messages:
            print(f"\nSummary for MTI {msg['mti']} ({msg['class']}):")
            print(f"All extracted field IDs: {msg['all_field_ids']}")
            print(f"Fields included in XML: {[f['id'] for f in msg['fields']]}")

        xml_root = generate_emvco_l3_xml(parsed_messages)

        # Write to output file
        with open(output_path, "wb") as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write(ET.tostring(xml_root, pretty_print=True, encoding="utf-8"))

        print(f"✅ XML written to {output_path}")
        return True

    except UnicodeDecodeError:
        print(f"Error: {input_path} is not a valid UTF-8 text file. Skipping.")
        return False
    except Exception as e:
        print(f"Error processing {input_path}: {str(e)}")
        return False

if __name__ == "__main__":
    # Define input and output directories
    input_folder = "VISA Logs"  # Folder containing log files
    output_folder = "xml_output"  # Folder to save XML files

    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)

    # Find all log files in the input folder (e.g., *.log, *.txt)
    log_files = glob.glob(os.path.join(input_folder, "*.log")) + glob.glob(os.path.join(input_folder, "*.txt"))

    if not log_files:
        print(f"No log files found in {input_folder}. Exiting.")
        exit(1)

    # Process each log file
    success_count = 0
    failure_count = 0

    for log_file in log_files:
        # Generate output XML file path
        base_name = os.path.basename(log_file)
        output_file = os.path.join(output_folder, base_name.rsplit('.', 1)[0] + ".xml")
        
        # Process the file
        if process_log_file(log_file, output_file):
            success_count += 1
        else:
            failure_count += 1

    # Summary
    print(f"\nProcessing complete. Successfully converted {success_count} files. Failed on {failure_count} files.")