"""Bounded fake-data workflow variations; these are not protection controls."""
from dataclasses import dataclass

MODES = ('repeated_sends','retry_after_503','reconnect_unique','duplicate_message',
         'conflicting_message','duplicate_attempt','ecapture_exit','etw_exit','native_io_stop')
FAULTS = ('ecapture_exit','etw_exit','native_io_stop')


@dataclass(frozen=True)
class LinkageExperiment:
    mode: str

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError('unsupported_linkage_experiment')

    @property
    def rounds(self):
        return 2 if self.mode in ('reconnect_unique','duplicate_message','conflicting_message') else 1

    @property
    def attempts(self):
        return 3 if self.mode == 'repeated_sends' else 2 if self.mode in ('retry_after_503','duplicate_attempt') else 1

    def arguments(self, role):
        arguments = ['--rounds',str(self.rounds)]
        if role == 'A':
            mode = {'duplicate_message':'repeat','conflicting_message':'conflict'}.get(self.mode,'unique')
            arguments += ['--message-mode',mode]
        else:
            arguments += ['--attempts',str(self.attempts)]
            if self.mode == 'duplicate_attempt': arguments += ['--same-attempt-id']
            if self.mode == 'retry_after_503': arguments += ['--retry-first-error']
            if self.mode in FAULTS: arguments += ['--pause-upload']
        return arguments

    @property
    def expects_complete(self):
        return self.mode in ('repeated_sends','retry_after_503')
