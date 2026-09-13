import * as vscode from 'vscode';
import { scanAll } from './scanners';
import { recordHit } from './reviewPrompt';

let diagnostics: vscode.DiagnosticCollection;

function refresh(context: vscode.ExtensionContext, document: vscode.TextDocument): void {
  if (document.languageId !== 'php') return;

  const hits = scanAll(document.getText());
  const result = hits.map((hit) => {
    const range = new vscode.Range(hit.line - 1, hit.startCol, hit.line - 1, hit.endCol);
    const diagnostic = new vscode.Diagnostic(range, hit.message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'PHP Security Companion';
    diagnostic.code = hit.rule;
    // A real security issue actually flagged -- dedup'd by file URI +
    // line so re-scanning on every keystroke doesn't inflate the count
    // towards the review prompt.
    recordHit(context, `${document.uri.toString()}:${hit.line - 1}`);
    return diagnostic;
  });
  diagnostics.set(document.uri, result);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('phpSecurityCompanion');
  context.subscriptions.push(diagnostics);

  vscode.workspace.textDocuments.forEach((doc) => refresh(context, doc));

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => refresh(context, doc)),
    vscode.workspace.onDidChangeTextDocument((event) => refresh(context, event.document)),
    vscode.workspace.onDidCloseTextDocument((document) => diagnostics.delete(document.uri)),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}
