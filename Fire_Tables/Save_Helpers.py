#!/usr/bin/env python3
import iptc
import re

# Get current values function
def get_current_values(row_of_boxes):
    # Input is just one row, a collection of boxes (options)
    
    # Look at each box, get the value, put it somewhere
    rule = {}
    chain_box = ''
    chain_box = row_of_boxes['input_output_forward_options']
    rule['input_options'] = chain_box.get()
    chain_box = row_of_boxes['source_ip_entry_box']
    rule['source_ip'] = chain_box.get()
    chain_box = row_of_boxes['destination_ip_entry_box']
    rule['destination_ip'] = chain_box.get() 
    chain_box = row_of_boxes['protocol_options']
    rule['protocol_options'] = chain_box.get()    
    chain_box = row_of_boxes['accept_or_drop_options']
    rule['accept_or_drop_options'] = chain_box.get()
    chain_box = row_of_boxes['source_port_entry_box']
    rule['source_port'] = chain_box.get()
    chain_box = row_of_boxes['destination_port_entry_box']
    rule['destination_port'] = chain_box.get()

    # Put values in a new dictionary (represents a single rule now)
    return rule


# IPTC function, takes the rule in and error checks
def iptc_to_ip_tables(the_rule):
    #print(the_rule)
    chain = ''
    rule = ''
    match = ''
    target = ''

    # Regular Expression to validate IPs
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
    
    # Get a dictionary of rules
    # Retrieve input options
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), (the_rule['input_options']))
    #print(chain.rules)

    rule = iptc.Rule()
    # rule.in_interface = "eth+"   
    # Retrieve IPs and error check entries
    if(re.search(regex, str(the_rule['source_ip']))):
        rule.src = the_rule['source_ip']
    #else:
        #print("FireTables: Rule Source IP set to anywhere")
    if(re.search(regex,str(the_rule['destination_ip']))):    
        rule.dst = the_rule['destination_ip']
    #else:
        #print("FireTables: Rule Destination IP set to anywhere")
    # Retrieve Accept or Drop options
    target = iptc.Target(rule, the_rule['accept_or_drop_options'])    
    rule.target = target
    # Retrieve Protocol
    rule.protocol = the_rule['protocol_options']   
    match = iptc.Match(rule, the_rule['protocol_options'])
    # Retrieve Ports and error check port entries
    if the_rule['protocol_options'] != 'icmp':
        if the_rule['source_port'] != "":
            if int(the_rule['source_port']) in range(65535):
                match.sport = the_rule['source_port']
        #else:
            #print("FireTables: Rule Source Port set to anywhere")
    
        if the_rule['destination_port'] != "":
            if int(the_rule['destination_port']) in range(65535):
                match.dport = the_rule['destination_port']
        #else:
            #print("FireTables: Rule Destination Port set to anywhere")
    rule.add_match(match)    
    # Insert rule into iptables
    chain.append_rule(rule)    

if __name__ == '__main__':
    get_current_values({})
    iptc_to_ip_tables({})
