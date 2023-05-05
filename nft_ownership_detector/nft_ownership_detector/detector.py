from copy import copy

from mythril.plugin import MythrilPlugin
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.analysis import solver
from mythril.exceptions import UnsatError
from mythril.analysis.potential_issues import (
    get_potential_issues_annotation,
    PotentialIssue,
)
from mythril.laser.smt import Extract, symbol_factory
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt import UGT


def detect_ownership_takeover(state):
    instruction = state.get_current_instruction()
    address, value = state.mstate.stack[-1], state.mstate.stack[-2]

    target_slot = 0
    target_offset = 0

    vulnerable_conditions = [
        address == target_slot,
        Extract(
            20 * 8 + target_offset,
            0 + target_offset,
            state.environment.active_account.storage[symbol_factory.BitVecVal(0, 256)],
        )
        != ACTORS.attacker,
        Extract(
            20 * 8 + target_offset,
            0 + target_offset,
            value,
        )
        == ACTORS.attacker,
        state.environment.sender == ACTORS.attacker,
    ]

    try:
        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints + vulnerable_conditions,
        )

        return Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            bytecode=state.environment.code.bytecode,
            title="Ownership Takeover",
            severity="High",
            description_head="Ownership takeover vulnerability detected.",
            description_tail="",
            transaction_sequence=transaction_sequence,
            gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
        )

    except UnsatError:
        pass

    return None


def detect_insufficient_balance_check_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        constraints += [
            UGT(
                state.world_state.balances[ACTORS.attacker],
                state.world_state.starting_balances[ACTORS.attacker],
            ),
            state.environment.sender == ACTORS.attacker,
            state.current_transaction.caller == state.current_transaction.origin,
        ]

        transaction_sequence = solver.get_transaction_sequence(
            state,
            constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "3")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Insufficient Buyer Wallet Balance Check not implementeds",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Insufficient Buyer Wallet Balance Check not implemented",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


def detect_seller_address_verification_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "1")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Seller Address Vulnerability detected",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Seller Address Vulnerability detected",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


def detect_buyer_address_verification_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "2")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Buyer Address Vulnerability detected",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Buyer Address Vulnerability detected",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


def detect_transaction_id_not_unique_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "4")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Transaction ID unique Check not implemented",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Transaction ID unique Check not implemented",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


def detect_purchase_price_mismatch_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "5")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Purchase Price/Transaction ID mismatch Check not implemented",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Purchase Price/Transaction ID mismatch Check not implemented",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


def detect_ownership_not_transfered_vulnerability(state):
    instruction = state.get_current_instruction()

    try:
        constraints = copy(state.world_state.constraints)
        solver.get_model(constraints)

        transaction_sequence = solver.get_transaction_sequence(
            state,
            state.world_state.constraints
            + [
                (len(state.environment.active_account.contract_name.split("_")) == 1)
                or (state.environment.active_account.contract_name.split("_")[1] == "6")
            ],
        )

        issue = Issue(
            contract=state.environment.active_account.contract_name,
            function_name=state.environment.active_function_name,
            address=instruction["address"],
            swc_id="000",
            title="Ownership not transfered Check not implemented",
            severity="High",
            bytecode=state.environment.code.bytecode,
            description_head="Ownership not transfered Check not implemented",
            transaction_sequence=transaction_sequence,
        )
        return issue
    except UnsatError:
        pass

    return None


class NFTOwnershipDetector(DetectionModule, MythrilPlugin):
    """This module checks for NFT ownership vulnerabilities"""

    # The following fields add some metadata to the plugin
    author = "Krishna Kushal"
    plugin_license = "MIT"
    plugin_type = "Detection Module"
    plugin_version = "0.0.1 "
    plugin_description = "This is a reference implementation of detection module plugin which finds NFT ownership takeover vulnerabilities."
    plugin_default_enabled = True
    entry_point = EntryPoint.CALLBACK
    pre_hooks = ["SSTORE"]

    def __init__(self):
        super().__init__()
        self._cache_address = {}

    def reset_module(self):
        """
        Resets the module
        :return:
        """
        super().reset_module()

    def _execute(self, state: GlobalState) -> None:
        """
        :param state:
        :return:
        """
        issues = self._analyze_state(state)
        self.issues.extend(issues)

    def _analyze_state(self, state: GlobalState) -> None:
        """
        :param state:
        :return:
        """

        #  Transfer NFT ownership from seller to buyer
        #  Check if seller wallet address is valid
        #  Check if buyer wallet address is valid
        #  Check buyer wallet balance
        #  Check if balance greater than purhase price
        #  Check for unique transaction ID
        #  Transfer funds from buyer to seller
        #  Check if seller wallet is credited with funds matching purchase price and matching transaction ID
        #  If transaction is successful change ownership of NFT from seller wallet address to buyer wallet address

        state = copy(state)

        issues = []
        if issue := detect_ownership_takeover(state):
            issues.append(issue)
        else:
            if issue := detect_seller_address_verification_vulnerability(state):
                issues.append(issue)

            if issue := detect_insufficient_balance_check_vulnerability(state):
                issues.append(issue)

            if issue := detect_buyer_address_verification_vulnerability(state):
                issues.append(issue)

            if issue := detect_purchase_price_mismatch_vulnerability(state):
                issues.append(issue)

            if issue := detect_transaction_id_not_unique_vulnerability(state):
                issues.append(issue)

            if issue := detect_purchase_price_mismatch_vulnerability(state):
                issues.append(issue)

        return issues
