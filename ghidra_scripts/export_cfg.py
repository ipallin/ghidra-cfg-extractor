# -*- coding: utf-8 -*-
"""Ghidra post-script that exports per-function control-flow graphs.

This script is executed inside a Ghidra headless session. It expects an output
path followed by an optional format specifier ("json" or "graphml").
"""

# This script relies on the Jython runtime that ships with Ghidra.

import json
import os

from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import ConsoleTaskMonitor


def _as_hex(address):
    if address is None:
        return None
    return "0x" + address.toString()


def _ensure_parent(path):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)


def _write_json(program_info, functions, output_path):
    _ensure_parent(output_path)
    with open(output_path, "w") as fd:
        json.dump(
            {"program": program_info, "functions": functions},
            fd,
            indent=2,
            sort_keys=True,
        )
    return True


def _infer_attr_type(kind, name):
    base_types = {
        ("graph", "entry_point"): "string",
        ("graph", "program_name"): "string",
        ("graph", "language_id"): "string",
        ("graph", "compiler"): "string",
        ("graph", "functionName"): "string",
        ("graph", "entryPoint"): "string",
        ("node", "function"): "string",
        ("node", "start"): "string",
        ("node", "end"): "string",
        ("node", "size"): "int",
        ("node", "instructions"): "string",
        ("node", "label"): "string",
        ("node", "address"): "string",
        ("node", "startAddress"): "string",
        ("node", "endAddress"): "string",
        ("node", "blockSize"): "int",
        ("edge", "flow_type"): "string",
        ("edge", "flowType"): "string",
    }
    return base_types.get((kind, name), "string")


def _register_key(graphml, key_id, target, name, value_type):
    key_elem = ET.SubElement(graphml, "key")
    key_elem.set("id", key_id)
    key_elem.set("for", target)
    key_elem.set("attr.name", name)
    key_elem.set("attr.type", value_type)


def _build_key_map(graphml, graph_attrs, node_attrs, edge_attrs):
    key_map = {}
    counter = 0

    def _assign(kind, names):
        nonlocal counter
        for name in sorted(names):
            key_id = "d{}".format(counter)
            counter += 1
            key_map[(kind, name)] = key_id
            _register_key(graphml, key_id, kind, name, _infer_attr_type(kind, name))

    _assign("graph", graph_attrs)
    _assign("node", node_attrs)
    _assign("edge", edge_attrs)
    return key_map


def _set_data_element(parent, key_map, kind, name, value):
    if value is None:
        return
    key = key_map.get((kind, name))
    if key is None:
        return
    data_elem = ET.SubElement(parent, "data")
    data_elem.set("key", key)
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(item) for item in value)
    data_elem.text = str(value)


def _write_graphml(program_info, functions, output_path):
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        printerr("xml.etree.ElementTree is unavailable; cannot export GraphML")
        return False

    graphml = ET.Element(
        "graphml",
        {
            "xmlns": "http://graphml.graphdrawing.org/xmlns",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:schemaLocation": (
                "http://graphml.graphdrawing.org/xmlns "
                "http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"
            ),
        },
    )

    graph_attrs = set(["entry_point", "program_name", "language_id", "compiler", "functionName", "entryPoint"])
    node_attrs = set(["function", "start", "end", "size", "instructions"])
    edge_attrs = set(["flow_type"])

    for function in functions:
        node_attrs.update(function.get("node_attribute_names", []))
        edge_attrs.update(function.get("edge_attribute_names", []))

    key_map = _build_key_map(graphml, graph_attrs, node_attrs, edge_attrs)

    for function in functions:
        function_name = function.get("name") or "function"
        entry_point = function.get("entry_point") or "unknown"
        graph_id = "%s@%s" % (function_name, entry_point)
        safe_graph_id = graph_id.replace(" ", "_")
        graph = ET.SubElement(graphml, "graph")
        graph.set("id", safe_graph_id)
        graph.set("edgedefault", "directed")

        _set_data_element(graph, key_map, "graph", "entry_point", entry_point)
        _set_data_element(graph, key_map, "graph", "functionName", function_name)
        _set_data_element(graph, key_map, "graph", "entryPoint", entry_point)
        _set_data_element(graph, key_map, "graph", "program_name", program_info.get("name"))
        _set_data_element(
            graph, key_map, "graph", "language_id", program_info.get("language_id")
        )
        _set_data_element(graph, key_map, "graph", "compiler", program_info.get("compiler"))

        node_prefix = safe_graph_id
        for block in function.get("blocks", []):
            block_id = block.get("id") or "block"
            node_id = "%s::%s" % (node_prefix, block_id)
            node = ET.SubElement(graph, "node")
            node.set("id", node_id)

            _set_data_element(node, key_map, "node", "function", function_name)
            _set_data_element(node, key_map, "node", "start", block.get("start"))
            _set_data_element(node, key_map, "node", "end", block.get("end"))
            _set_data_element(node, key_map, "node", "size", block.get("size"))

            instructions = block.get("instructions", [])
            if instructions:
                representation = [instr.get("representation") or "" for instr in instructions]
                _set_data_element(node, key_map, "node", "instructions", "\n".join(representation))

            for name, value in block.get("ghidra_attributes", {}).items():
                _set_data_element(node, key_map, "node", name, value)

        edge_index = 0
        for edge in function.get("edges", []):
            edge_elem = ET.SubElement(graph, "edge")
            edge_elem.set("id", "%s::e%d" % (node_prefix, edge_index))
            edge_index += 1

            source = "%s::%s" % (node_prefix, edge.get("source") or "")
            target = "%s::%s" % (node_prefix, edge.get("target") or "")
            edge_elem.set("source", source)
            edge_elem.set("target", target)

            _set_data_element(edge_elem, key_map, "edge", "flow_type", edge.get("type"))

            for name, value in edge.get("ghidra_attributes", {}).items():
                _set_data_element(edge_elem, key_map, "edge", name, value)

    _ensure_parent(output_path)
    tree = ET.ElementTree(graphml)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)
    return True


def run():
    args = getScriptArgs()
    if not args:
        printerr(
            "Missing output path argument. Usage: export_cfg.py <output> [json|graphml]"
        )
        return

    output_path = os.path.abspath(args[0])
    output_format = "graphml"
    if len(args) > 1 and args[1]:
        output_format = args[1].strip().lower()
    entry_address = None
    if len(args) > 2 and args[2]:
        entry_address = args[2].strip()
        if not entry_address:
            entry_address = None

    monitor = getMonitor()
    if monitor is None:
        monitor = ConsoleTaskMonitor()

    program = currentProgram
    function_manager = program.getFunctionManager()
    block_model = SimpleBlockModel(program)
    listing = program.getListing()

    program_info = {
        "name": program.getName(),
        "language_id": program.getLanguage().getLanguageID().getIdAsString(),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
    }
    functions = []

    target_function = None

    if entry_address:
        try:
            address = toAddr(entry_address)
        except Exception:  # noqa: BLE001 - ghidra provides non-standard exceptions
            printerr("Invalid entry address '{}'.".format(entry_address))
            return
        target_function = function_manager.getFunctionAt(address)
        if target_function is None:
            printerr(
                "No function found at entry address '{}'. Provide a valid address.".format(
                    entry_address
                )
            )
            return
    else:
        function_iter = function_manager.getFunctions(True)
        while function_iter.hasNext():
            candidate = function_iter.next()
            if candidate.getName() == "main":
                target_function = candidate
                break

        if target_function is None:
            printerr(
                "Function 'main' was not found. Re-run with --entry-address to specify its location."
            )
            return

    monitor.setMessage("Exporting CFG for {}".format(target_function.getName()))

    body = target_function.getBody()
    block_iter = block_model.getCodeBlocksContaining(body, monitor)

    blocks = {}
    block_list = []
    edges = []
    node_attribute_names = set(["label", "address", "startAddress", "endAddress", "blockSize"])
    edge_attribute_names = set(["flowType"])

    while block_iter.hasNext() and not monitor.isCancelled():
        block = block_iter.next()
        start = _as_hex(block.getFirstStartAddress())
        end = _as_hex(block.getMaxAddress())
        size = block.getNumAddresses()

        block_label_lines = []

        block_info = {
            "id": start,
            "start": start,
            "end": end,
            "size": int(size),
        }

        instructions = []
        inst_iter = listing.getInstructions(block, True)
        while inst_iter.hasNext() and not monitor.isCancelled():
            instruction = inst_iter.next()
            operands = []
            for op_index in range(instruction.getNumOperands()):
                operands.append(instruction.getDefaultOperandRepresentation(op_index))
            representation = instruction.toString()
            address_text = _as_hex(instruction.getAddress())
            instructions.append(
                {
                    "address": address_text,
                    "mnemonic": instruction.getMnemonicString(),
                    "operands": operands,
                    "representation": representation,
                }
            )
            block_label_lines.append("{}: {}".format(address_text, representation))

        block_info["instructions"] = instructions

        ghidra_block_attrs = {
            "label": "\n".join(block_label_lines),
            "address": start,
            "startAddress": start,
            "endAddress": end,
            "blockSize": int(size),
        }

        block_info["ghidra_attributes"] = ghidra_block_attrs
        node_attribute_names.update(ghidra_block_attrs.keys())

        block_list.append(block_info)
        blocks[start] = block

    for block_id, block in blocks.items():
        dest_iter = block.getDestinations(monitor)
        while dest_iter.hasNext() and not monitor.isCancelled():
            reference = dest_iter.next()
            dest_block = reference.getDestinationBlock()
            if dest_block is None:
                continue
            dest_id = _as_hex(dest_block.getFirstStartAddress())
            flow_type = str(reference.getFlowType())
            edge_info = {
                "source": block_id,
                "target": dest_id,
                "type": flow_type,
                "ghidra_attributes": {"flowType": flow_type},
            }
            edges.append(edge_info)
            edge_attribute_names.update(edge_info["ghidra_attributes"].keys())

    functions.append(
        {
            "name": target_function.getName(),
            "entry_point": _as_hex(target_function.getEntryPoint()),
            "blocks": block_list,
            "edges": edges,
            "node_attribute_names": sorted(node_attribute_names),
            "edge_attribute_names": sorted(edge_attribute_names),
        }
    )

    writers = {
        "json": _write_json,
        "graphml": _write_graphml,
    }

    writer = writers.get(output_format)
    if writer is None:
        printerr("Unsupported output format: {}".format(output_format))
        return

    if not writer(program_info, functions, output_path):
        printerr("Failed to write CFG in {} format".format(output_format))
        return


run()
