import * as vscode from 'vscode';
import { scanAll } from './scanners';

let diagnostics: vscode.DiagnosticCollection;

function refresh(document: vscode.TextDocument): void {
  if (document.languageId !== 'php') return;

  const hits = scanAll(document.getText());
  const result = hits.map((hit) => {
    const range = new vscode.Range(hit.line - 1, hit.startCol, hit.line - 1, hit.endCol);
    const diagnostic = new vscode.Diagnostic(range, hit.message, vscode.DiagnosticSeverity.Warning);
    diagnostic.source = 'PHP Security Companion';
    diagnostic.code = hit.rule;
    return diagnostic;
  });
  diagnostics.set(document.uri, result);
}

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('phpSecurityCompanion');
  context.subscriptions.push(diagnostics);

  vscode.workspace.textDocuments.forEach(refresh);

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(refresh),
    vscode.workspace.onDidChangeTextDocument((event) => refresh(event.document)),
    vscode.workspace.onDidCloseTextDocument((document) => diagnostics.delete(document.uri)),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
}
