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

    key_defs = [
        ("d0", "node", "function", "string"),
        ("d1", "node", "start", "string"),
        ("d2", "node", "end", "string"),
        ("d3", "node", "size", "int"),
        ("d4", "graph", "entry_point", "string"),
        ("d5", "edge", "flow_type", "string"),
        ("d6", "graph", "program_name", "string"),
        ("d7", "graph", "language_id", "string"),
        ("d8", "graph", "compiler", "string"),
        ("d9", "node", "instructions", "string"),
    ]

    for key_id, target, name, value_type in key_defs:
        key_elem = ET.SubElement(graphml, "key")
        key_elem.set("id", key_id)
        key_elem.set("for", target)
        key_elem.set("attr.name", name)
        key_elem.set("attr.type", value_type)

    for function in functions:
        function_name = function.get("name") or "function"
        entry_point = function.get("entry_point") or "unknown"
        graph_id = "%s@%s" % (function_name, entry_point)
        safe_graph_id = graph_id.replace(" ", "_")
        graph = ET.SubElement(graphml, "graph")
        graph.set("id", safe_graph_id)
        graph.set("edgedefault", "directed")

        entry_data = ET.SubElement(graph, "data")
        entry_data.set("key", "d4")
        entry_data.text = entry_point

        program_name = ET.SubElement(graph, "data")
        program_name.set("key", "d6")
        program_name.text = program_info.get("name") or ""

        language_id = ET.SubElement(graph, "data")
        language_id.set("key", "d7")
        language_id.text = program_info.get("language_id") or ""

        compiler = ET.SubElement(graph, "data")
        compiler.set("key", "d8")
        compiler.text = program_info.get("compiler") or ""

        node_prefix = safe_graph_id
        for block in function.get("blocks", []):
            block_id = block.get("id") or "block"
            node_id = "%s::%s" % (node_prefix, block_id)
            node = ET.SubElement(graph, "node")
            node.set("id", node_id)

            node_func = ET.SubElement(node, "data")
            node_func.set("key", "d0")
            node_func.text = function_name

            node_start = ET.SubElement(node, "data")
            node_start.set("key", "d1")
            node_start.text = block.get("start") or ""

            node_end = ET.SubElement(node, "data")
            node_end.set("key", "d2")
            node_end.text = block.get("end") or ""

            node_size = ET.SubElement(node, "data")
            node_size.set("key", "d3")
            node_size.text = str(block.get("size"))

            instructions = block.get("instructions", [])
            if instructions:
                node_instr = ET.SubElement(node, "data")
                node_instr.set("key", "d9")
                node_instr.text = "\n".join(
                    instr.get("representation") or "" for instr in instructions
                )

        edge_index = 0
        for edge in function.get("edges", []):
            edge_elem = ET.SubElement(graph, "edge")
            edge_elem.set("id", "%s::e%d" % (node_prefix, edge_index))
            edge_index += 1

            source = "%s::%s" % (node_prefix, edge.get("source") or "")
            target = "%s::%s" % (node_prefix, edge.get("target") or "")
            edge_elem.set("source", source)
            edge_elem.set("target", target)

            edge_type = ET.SubElement(edge_elem, "data")
            edge_type.set("key", "d5")
            edge_type.text = edge.get("type") or ""

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

    # If entry_address is the special value "ALL", export all functions.
    export_all = False
    if entry_address is not None and entry_address.upper() == "ALL":
        export_all = True
        entry_address = None

    if not export_all:
        if entry_address:
            try:
                address = toAddr(entry_address)
            except Exception:  # noqa: BLE001 - ghidra provides non-standard exceptions
                printerr("Invalid entry address '{}' .".format(entry_address))
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
                    "Function 'main' was not found. Re-run with --entry-address or --all-functions."
                )
                return

    if export_all:
        monitor.setMessage("Exporting CFGs for all functions")
    else:
        monitor.setMessage("Exporting CFG for {}".format(target_function.getName()))

    body = target_function.getBody()
    block_iter = block_model.getCodeBlocksContaining(body, monitor)

    def _export_function(fn, functions_out):
        body = fn.getBody()
        block_iter = block_model.getCodeBlocksContaining(body, monitor)

        blocks = {}
        block_list = []
        edges = []

        while block_iter.hasNext() and not monitor.isCancelled():
            block = block_iter.next()
            start = _as_hex(block.getFirstStartAddress())
            end = _as_hex(block.getMaxAddress())
            size = block.getNumAddresses()

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
                instructions.append(
                    {
                        "address": _as_hex(instruction.getAddress()),
                        "mnemonic": instruction.getMnemonicString(),
                        "operands": operands,
                        "representation": instruction.toString(),
                    }
                )

            block_info["instructions"] = instructions

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
                edges.append(
                    {
                        "source": block_id,
                        "target": dest_id,
                        "type": str(reference.getFlowType()),
                    }
                )

        functions_out.append(
            {
                "name": fn.getName(),
                "entry_point": _as_hex(fn.getEntryPoint()),
                "blocks": block_list,
                "edges": edges,
            }
        )

    if export_all:
        function_iter = function_manager.getFunctions(True)
        count = 0
        while function_iter.hasNext():
            fn = function_iter.next()
            _export_function(fn, functions)
            count += 1
        if count == 0:
            # Still write an empty output file to signal processing completed.
            printerr("No functions discovered to export. Writing empty output.")
    else:
        _export_function(target_function, functions)

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
