import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scanSqlInjection,
  scanFunctionInjection,
  scanOpenRedirect,
  scanFileInclusion,
  scanShellInjection,
  scanAll,
} from '../scanners';

test('scanSqlInjection flags mysqli_query with double-quoted interpolation', () => {
  const hits = scanSqlInjection('mysqli_query($conn, "SELECT * FROM users WHERE id = $id");');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'sql-injection');
  assert.equal(hits[0].line, 1);
});

test('scanSqlInjection flags ->query with concatenation', () => {
  const hits = scanSqlInjection('$pdo->query("SELECT * FROM t WHERE x=" . $x);');
  assert.equal(hits.length, 1);
});

test('scanSqlInjection does not flag a prepared statement placeholder', () => {
  const hits = scanSqlInjection('$pdo->query("SELECT * FROM users WHERE id = ?");');
  assert.equal(hits.length, 0);
});

test('scanSqlInjection ignores commented-out lines', () => {
  const hits = scanSqlInjection('// mysqli_query($conn, "SELECT * WHERE id = $id");');
  assert.equal(hits.length, 0);
});

test('scanFunctionInjection flags call_user_func with a superglobal', () => {
  const hits = scanFunctionInjection('call_user_func($_GET["fn"]);');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'function-injection');
});

test('scanFunctionInjection does not flag a static callable', () => {
  const hits = scanFunctionInjection('call_user_func("strtoupper", $x);');
  assert.equal(hits.length, 0);
});

test('scanOpenRedirect flags header(Location: ...) with a superglobal', () => {
  const hits = scanOpenRedirect('header("Location: " . $_GET["next"]);');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'open-redirect');
});

test('scanOpenRedirect does not flag a header() call without Location', () => {
  const hits = scanOpenRedirect('header("Content-Type: " . $_GET["type"]);');
  assert.equal(hits.length, 0);
});

test('scanFileInclusion flags include with a superglobal path', () => {
  const hits = scanFileInclusion('include($_GET["page"] . ".php");');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'file-inclusion');
});

test('scanFileInclusion flags require_once too', () => {
  const hits = scanFileInclusion('require_once($_REQUEST["module"]);');
  assert.equal(hits.length, 1);
});

test('scanFileInclusion does not flag a static include path', () => {
  const hits = scanFileInclusion('include("config.php");');
  assert.equal(hits.length, 0);
});

test('scanShellInjection flags exec with interpolation', () => {
  const hits = scanShellInjection('exec("ls $dir");');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule, 'shell-injection');
});

test('scanShellInjection flags system with concatenation', () => {
  const hits = scanShellInjection('system("ping " . $host);');
  assert.equal(hits.length, 1);
});

test('scanShellInjection does not flag a static command', () => {
  const hits = scanShellInjection('system("uptime");');
  assert.equal(hits.length, 0);
});

test('scanAll combines all 5 scanners', () => {
  const text = [
    'mysqli_query($conn, "SELECT * WHERE id = $id");',
    'call_user_func($_GET["fn"]);',
    'header("Location: " . $_GET["next"]);',
    'include($_GET["page"]);',
    'exec("ls $dir");',
  ].join('\n');
  const hits = scanAll(text);
  assert.equal(hits.length, 5);
  const rules = hits.map((h) => h.rule).sort();
  assert.deepEqual(rules, [
    'file-inclusion',
    'function-injection',
    'open-redirect',
    'shell-injection',
    'sql-injection',
  ]);
});
