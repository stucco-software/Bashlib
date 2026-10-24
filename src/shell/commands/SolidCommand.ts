import { SolidShell } from '../../commands/solid-shell';
import { Command } from 'commander';
export default abstract class SolidCommand { 
  shell?: SolidShell;
  mayExit: boolean;
  program?: Command;
  // Read global options lazily: they only exist after commander has parsed argv.
  get programopts(): any { return this.program?.opts() ?? {}; }
  mayUseCurrentContainer: boolean;

  constructor(shell?: SolidShell, mayExit = false, mayUseCurrentContainer = false) { 
    this.shell = shell;
    this.mayExit = mayExit;
    this.mayUseCurrentContainer = mayUseCurrentContainer;
  }

  abstract addCommand(program: Command): Command; 
}