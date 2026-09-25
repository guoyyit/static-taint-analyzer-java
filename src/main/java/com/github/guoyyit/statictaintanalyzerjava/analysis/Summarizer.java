package com.github.guoyyit.statictaintanalyzerjava.analysis;

import com.github.guoyyit.statictaintanalyzerjava.lang.Ast;
import com.github.guoyyit.statictaintanalyzerjava.rules.AnalysisRules;

import java.util.ArrayList;
import java.util.List;

/**
 * Extracts a {@link FunctionSummary} from a function AST. Pure and deterministic:
 * depends only on the function text and the rule set, so it is cacheable per
 * file content hash. Nested calls are lowered into synthetic temp variables so
 * the global flow graph stays flat. Sanitizer calls emit no flow edge (taint cut).
 */
public final class Summarizer {

    private final List<FunctionSummary.AssignFact> assignments = new ArrayList<>();
    private final List<FunctionSummary.CallFact> calls = new ArrayList<>();
    private final List<FunctionSummary.ReturnFact> returns = new ArrayList<>();
    private final List<FunctionSummary.SourceFact> sources = new ArrayList<>();
    private final List<FunctionSummary.SinkFact> sinks = new ArrayList<>();
    private int tempCounter;
    private int callCounter;
    private String file;
    private AnalysisRules rules;

    public synchronized FunctionSummary summarize(Ast.FunctionDef fn, AnalysisRules rules) {
        this.assignments.clear();
        this.calls.clear();
        this.returns.clear();
        this.sources.clear();
        this.sinks.clear();
        this.tempCounter = 0;
        this.callCounter = 0;
        this.file = fn.file();
        this.rules = rules;
        summarizeStmts(fn.body());
        return new FunctionSummary(fn.name(), fn.file(), fn.params(),
                List.copyOf(assignments), List.copyOf(calls), List.copyOf(returns),
                List.copyOf(sources), List.copyOf(sinks));
    }

    private void summarizeStmts(List<Ast.Stmt> stmts) {
        for (Ast.Stmt stmt : stmts) {
            if (stmt instanceof Ast.Assign a) {
                lowerAssign(a.target(), a.value(), a.line());
            } else if (stmt instanceof Ast.ExprStmt e) {
                if (e.expr() instanceof Ast.Call call) {
                    lowerCall(null, call, e.line());
                }
            } else if (stmt instanceof Ast.Return r) {
                returns.add(new FunctionSummary.ReturnFact(lowerVars(r.value()), r.line()));
            } else if (stmt instanceof Ast.If i) {
                summarizeStmts(i.thenBody());
                summarizeStmts(i.elseBody());
            } else if (stmt instanceof Ast.While w) {
                summarizeStmts(w.body());
            }
        }
    }

    private void lowerAssign(String target, Ast.Expr expr, int line) {
        if (expr instanceof Ast.Call call) {
            lowerCall(target, call, line);
            return;
        }
        List<String> vars = lowerVars(expr);
        if (!vars.isEmpty()) {
            assignments.add(new FunctionSummary.AssignFact(target, vars, line));
        }
    }

    /** Lowers an expression to the list of variables carrying its value. */
    private List<String> lowerVars(Ast.Expr expr) {
        List<String> vars = new ArrayList<>();
        collectVars(expr, vars);
        return vars;
    }

    private void collectVars(Ast.Expr expr, List<String> out) {
        if (expr instanceof Ast.Ident id) {
            out.add(id.name());
        } else if (expr instanceof Ast.Binary b) {
            collectVars(b.left(), out);
            collectVars(b.right(), out);
        } else if (expr instanceof Ast.Call call) {
            String tmp = freshTemp();
            lowerCall(tmp, call, call.line());
            out.add(tmp);
        }
    }

    private void lowerCall(String dst, Ast.Call call, int line) {
        List<String> argVars = new ArrayList<>();
        for (Ast.Expr arg : call.args()) {
            collectVars(arg, argVars);
        }
        if (rules.isSanitizer(call.callee())) {
            // Sanitizer cuts the taint: no edge from args to dst.
            return;
        }
        String callSiteId = file + ":" + line + ":" + (callCounter++);
        calls.add(new FunctionSummary.CallFact(callSiteId, call.callee(), List.copyOf(argVars), dst, line));
        AnalysisRules.SourceRule source = rules.matchSource(call.callee());
        if (source != null && dst != null) {
            sources.add(new FunctionSummary.SourceFact(source.id(), dst, line));
        }
        AnalysisRules.SinkRule sink = rules.matchSink(call.callee());
        if (sink != null) {
            sinks.add(new FunctionSummary.SinkFact(sink.id(), List.copyOf(argVars), line));
        }
    }

    private String freshTemp() {
        return "$tmp" + (tempCounter++);
    }
}
