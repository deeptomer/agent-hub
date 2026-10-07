"""Hand-written PostgreSQL for the statements the rules engine escalates. Used ONLY by tests as a stand-in for Claude
(FakeLLM) to exercise the agent plumbing; they are not shipped as product behaviour and the app never reads them."""

ORG_TREE = """WITH RECURSIVE org AS (
  SELECT 1 AS depth, e.full_name, e.employee_id, ARRAY[e.full_name::text] AS path_arr, e.full_name::text AS path_txt
  FROM employees e WHERE e.manager_id IS NULL
  UNION ALL
  SELECT o.depth + 1, e.full_name, e.employee_id, o.path_arr || e.full_name::text, o.path_txt || ' > ' || e.full_name
  FROM employees e JOIN org o ON e.manager_id = o.employee_id
)
SELECT depth AS DEPTH, LPAD(' ', 2 * (depth - 1)) || full_name AS INDENTED_NAME, ' > ' || path_txt AS PATH, employee_id AS EMPLOYEE_ID
FROM org ORDER BY path_arr"""

KEEP = """SELECT department, (ARRAY_AGG(full_name ORDER BY salary DESC))[1] AS top_earner, MAX(salary) AS top_salary
FROM employees GROUP BY department"""

PIVOT = """SELECT category,
  SUM(rev) FILTER (WHERE qtr = '1') AS q1, SUM(rev) FILTER (WHERE qtr = '2') AS q2,
  SUM(rev) FILTER (WHERE qtr = '3') AS q3, SUM(rev) FILTER (WHERE qtr = '4') AS q4
FROM (
  SELECT p.category, TO_CHAR(o.order_date, 'Q') AS qtr, i.quantity * i.unit_price AS rev
  FROM orders o JOIN order_items i ON o.order_id = i.order_id JOIN products p ON p.product_id = i.product_id
) t GROUP BY category"""

PACKAGE = """CREATE SCHEMA IF NOT EXISTS pkg_order_mgmt;

CREATE OR REPLACE FUNCTION pkg_order_mgmt.calc_order_total(p_order_id bigint) RETURNS numeric
LANGUAGE plpgsql AS $$
DECLARE v_total numeric(14,2);
BEGIN
  SELECT COALESCE(SUM(quantity * unit_price), 0) INTO v_total FROM order_items WHERE order_id = p_order_id;
  RETURN v_total;
END $$;

CREATE OR REPLACE FUNCTION pkg_order_mgmt.ship_order(p_order_id bigint, OUT p_result text)
LANGUAGE plpgsql AS $$
DECLARE
  v_status orders.status%TYPE; v_total numeric; rec record; v_rows integer;
BEGIN
  SELECT status INTO STRICT v_status FROM orders WHERE order_id = p_order_id FOR UPDATE;
  IF v_status <> 'NEW' THEN p_result := 'ERROR: order not in NEW status'; RETURN; END IF;
  FOR rec IN SELECT product_id, quantity FROM order_items WHERE order_id = p_order_id LOOP
    UPDATE products SET stock_qty = stock_qty - rec.quantity WHERE product_id = rec.product_id;
    GET DIAGNOSTICS v_rows = ROW_COUNT;
    IF v_rows = 0 THEN RAISE EXCEPTION 'Missing product %', rec.product_id USING ERRCODE = 'P0001'; END IF;
  END LOOP;
  v_total := pkg_order_mgmt.calc_order_total(p_order_id);
  UPDATE orders SET status = 'SHP', total_amount = v_total WHERE order_id = p_order_id;
  INSERT INTO audit_log (audit_id, table_name, action, action_ts, details)
  VALUES (nextval('seq_audit_id'), 'ORDERS', 'SHIP', CURRENT_TIMESTAMP, 'Order ' || p_order_id || ' shipped, total=' || v_total::text);
  p_result := 'OK';
EXCEPTION
  WHEN no_data_found THEN p_result := 'ERROR: order not found';
  WHEN OTHERS THEN p_result := 'ERROR: ' || SQLERRM;
END $$;

CREATE OR REPLACE FUNCTION pkg_order_mgmt.cancel_order(p_order_id bigint) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  UPDATE orders SET status = 'CAN' WHERE order_id = p_order_id;
  UPDATE products p SET stock_qty = p.stock_qty + i.quantity FROM order_items i
   WHERE i.product_id = p.product_id AND i.order_id = p_order_id;
END $$;"""


def answers():
    def ans(sql, why="golden test answer"):
        return {"postgres_sql": sql, "explanation": why, "assumptions": [], "needs_manual_review": False}
    return {
        "SYS_CONNECT_BY_PATH": ans(ORG_TREE), "KEEP (DENSE_RANK": ans(KEEP), "PIVOT (": ans(PIVOT),
        "PACKAGE PKG_ORDER_MGMT": ans(PACKAGE),
    }
