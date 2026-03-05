using namespace System.Management.Automation.Language
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

while ($true) {
    $ln = [Console]::In.ReadLine()
    if ($null -eq $ln) { break }
    try {
        $req  = $ln | ConvertFrom-Json
        $errs = [ParseError[]]@()
        $toks = [Token[]]@()
        $ast  = [Parser]::ParseInput($req.command, [ref]$toks, [ref]$errs)

        $vars   = @{}
        $htVars = @{}
        $cmds = [System.Collections.Generic.List[object]]::new()
        foreach ($block in @($ast.BeginBlock, $ast.ProcessBlock, $ast.EndBlock)) {
            if ($null -eq $block) { continue }
            foreach ($stmt in $block.Statements) {
                # Record $var = "literal" and $var = @{Key="value"} assignments.
                if ($stmt -is [AssignmentStatementAst]) {
                    try {
                        $lhs = $stmt.Left
                        $rhs = $stmt.Right
                        if ($rhs -is [CommandExpressionAst] -and
                            $rhs.Expression -is [StringConstantExpressionAst]) {
                            if ($lhs -is [VariableExpressionAst]) {
                                $vars[$lhs.VariablePath.UserPath] = $rhs.Expression.Value
                            } elseif ($lhs -is [ConvertExpressionAst] -and
                                      $lhs.Child -is [VariableExpressionAst]) {
                                $vars[$lhs.Child.VariablePath.UserPath] = $rhs.Expression.Value
                            }
                        } elseif ($rhs -is [CommandExpressionAst] -and $rhs.Expression -is [HashtableAst]) {
                            $vn = if ($lhs -is [VariableExpressionAst]) { $lhs.VariablePath.UserPath }
                                  elseif ($lhs -is [ConvertExpressionAst] -and $lhs.Child -is [VariableExpressionAst]) { $lhs.Child.VariablePath.UserPath }
                            if ($vn) {
                                $hv = [System.Collections.Generic.List[string]]::new()
                                foreach ($kvp in $rhs.Expression.KeyValuePairs) {
                                    $kvp.Item2.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) | ForEach-Object { $hv.Add($_.Value) }
                                }
                                $htVars[$vn] = $hv.ToArray()
                            }
                        }
                    } catch { $null = $_ }
                }
                # CommandAst nodes (cmdlets) — recurse into nested scriptblocks.
                $stmt.FindAll({ param($n) $n -is [CommandAst] }, $true) | ForEach-Object {
                    $nm = $_.GetCommandName()
                    if ($nm) {  # filters $null and "" (e.g. & "" arg)
                        $ag = [System.Collections.Generic.List[string]]::new()
                        $_.CommandElements | Select-Object -Skip 1 | ForEach-Object {
                            try {
                                if ($_ -is [StringConstantExpressionAst]) {
                                    $ag.Add($_.Value)
                                } elseif ($_ -is [VariableExpressionAst]) {
                                    $k = $_.VariablePath.UserPath
                                    if ($_.Splatted) { if ($htVars.ContainsKey($k)) { foreach ($v in $htVars[$k]) { $ag.Add($v) } } }
                                    else { if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) } }
                                } elseif ($_ -is [ExpandableStringExpressionAst]) {
                                    # Literal expandable string (no vars) or single $var.
                                    $nx = @($_.NestedExpressions)
                                    if ($nx.Count -eq 0) { $ag.Add($_.Value) }
                                    elseif ($nx.Count -eq 1 -and $nx[0] -is [VariableExpressionAst]) {
                                        $k = $nx[0].VariablePath.UserPath
                                        if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                    }
                                } elseif ($_ -is [ArrayExpressionAst] -or $_ -is [ArrayLiteralAst]) {
                                    # @("a","b") or "a","b" — extract literal strings only.
                                    # $false: don't descend into $(cmd) subexpressions.
                                    $_.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) |
                                        ForEach-Object { $ag.Add($_.Value) }
                                } elseif ($_ -is [CommandParameterAst]) {
                                    $ag.Add('-' + $_.ParameterName)
                                    # -Flag:value colon syntax.
                                    if ($null -ne $_.Argument) {
                                        if ($_.Argument -is [StringConstantExpressionAst]) {
                                            $ag.Add($_.Argument.Value)
                                        } elseif ($_.Argument -is [VariableExpressionAst]) {
                                            $k = $_.Argument.VariablePath.UserPath
                                            if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                        } elseif ($_.Argument -is [ExpandableStringExpressionAst]) {
                                            $nx = @($_.Argument.NestedExpressions)
                                            if ($nx.Count -eq 0) { $ag.Add($_.Argument.Value) }
                                            elseif ($nx.Count -eq 1 -and $nx[0] -is [VariableExpressionAst]) {
                                                $k = $nx[0].VariablePath.UserPath
                                                if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                            }
                                        } elseif ($_.Argument -is [ArrayExpressionAst] -or
                                                  $_.Argument -is [ArrayLiteralAst]) {
                                            $_.Argument.FindAll({ param($n) $n -is [StringConstantExpressionAst] }, $false) |
                                                ForEach-Object { $ag.Add($_.Value) }
                                        }
                                    }
                                }
                            } catch { $null = $_ }
                        }
                        # Pipeline input: "/path" | Get-Content → treat preceding string
                        # expressions (CommandExpressionAst) as implicit positional args.
                        $pp = $_.Parent
                        if ($pp -is [PipelineAst]) {
                            $ix = [array]::IndexOf([object[]]$pp.PipelineElements, $_)
                            for ($i = 0; $i -lt $ix; $i++) {
                                $seg = $pp.PipelineElements[$i]
                                if ($seg -is [CommandExpressionAst]) {
                                    $e = $seg.Expression
                                    try {
                                        if ($e -is [StringConstantExpressionAst]) {
                                            $ag.Add($e.Value)
                                        } elseif ($e -is [ExpandableStringExpressionAst]) {
                                            $nx = @($e.NestedExpressions)
                                            if ($nx.Count -eq 0) { $ag.Add($e.Value) }
                                            elseif ($nx.Count -eq 1 -and $nx[0] -is [VariableExpressionAst]) {
                                                $k = $nx[0].VariablePath.UserPath
                                                if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                            }
                                        } elseif ($e -is [VariableExpressionAst]) {
                                            $k = $e.VariablePath.UserPath
                                            if ($vars.ContainsKey($k)) { $ag.Add($vars[$k]) }
                                        }
                                    } catch { $null = $_ }
                                }
                            }
                        }
                        # Redirect paths: > out.txt or < in.txt
                        $redirOut = [System.Collections.Generic.List[string]]::new()
                        $redirIn  = [System.Collections.Generic.List[string]]::new()
                        foreach ($r in $_.Redirections) {
                            try {
                                $f = $r.File
                                if ($f -is [StringConstantExpressionAst]) {
                                    if ($r.FromStream -eq [RedirectionStream]::Input) {
                                        $redirIn.Add($f.Value)
                                    } else {
                                        $redirOut.Add($f.Value)
                                    }
                                }
                            } catch { $null = $_ }
                        }
                        $hasSubst = $false
                        foreach ($el in ($_.CommandElements | Select-Object -Skip 1)) {
                            if ($el -isnot [StringConstantExpressionAst] -and
                                $el -isnot [CommandParameterAst]) {
                                $hasSubst = $true; break
                            }
                            if ($el -is [CommandParameterAst] -and
                                $null -ne $el.Argument -and
                                $el.Argument -isnot [StringConstantExpressionAst]) {
                                $hasSubst = $true; break
                            }
                        }
                        $cmds.Add([PSCustomObject]@{
                            name           = $nm
                            args           = [string[]]$ag.ToArray()
                            redir_paths    = [string[]]$redirOut.ToArray()
                            redir_in_paths = [string[]]$redirIn.ToArray()
                            has_subst      = $hasSubst
                        })
                    }
                }
                # .NET static calls: [Type]::Method(args) — emitted as "Type::Method".
                # Go normalizes names containing '::' to lowercase for DB lookup.
                $stmt.FindAll({param($n)$n-is[InvokeMemberExpressionAst]-and$n.Static},$true)|ForEach-Object{try{if($_.Expression-is[TypeExpressionAst]-and$_.Member-is[StringConstantExpressionAst]){$da=[System.Collections.Generic.List[string]]::new();foreach($a in $_.Arguments){if($a-is[StringConstantExpressionAst]){$da.Add($a.Value)}};$cmds.Add([PSCustomObject]@{name=$_.Expression.TypeName.FullName+'::'+$_.Member.Value;args=[string[]]$da.ToArray();redir_paths=[string[]]@();redir_in_paths=[string[]]@();has_subst=$false})}}catch{$null=$_}}
            }
        }

        $resp = [PSCustomObject]@{
            commands    = [object[]]$cmds.ToArray()
            parseErrors = [string[]]@($errs | ForEach-Object { $_.Message })
        }
        # Strip newlines: response must be exactly one line for bufio.Scanner.
        ($resp | ConvertTo-Json -Compress -Depth 5) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    } catch {
        ([PSCustomObject]@{
            commands    = [object[]]@()
            parseErrors = [string[]]@($_.Exception.Message)
        } | ConvertTo-Json -Compress) -replace '\r\n|\r|\n', ''
        [Console]::Out.Flush()
    }
}
