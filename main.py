from multiprocessing import freeze_support

import config
from loss_analyzer import LossAnalyzer

if __name__ == "__main__":
    if config.use_multiprocessing:
        freeze_support()

    loss_analyzer: LossAnalyzer = LossAnalyzer()
    loss_analyzer.find_loss()
