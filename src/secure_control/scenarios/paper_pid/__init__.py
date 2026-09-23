"""论文 §VII 的明文 PID 控制器设计；不包含未经核实的 plant。"""

from .pid import PaperPidDesign, paper_sec_vii_controller_spec

__all__ = ["PaperPidDesign", "paper_sec_vii_controller_spec"]
