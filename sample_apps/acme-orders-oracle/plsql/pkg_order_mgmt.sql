-- Oracle PL/SQL package used by the Java layer (PKG_ORDER_MGMT.SHIP_ORDER etc.)

CREATE OR REPLACE PACKAGE PKG_ORDER_MGMT AS
    c_max_discount CONSTANT NUMBER := 40;

    PROCEDURE SHIP_ORDER(p_order_id IN NUMBER, p_result OUT VARCHAR2);
    FUNCTION  CALC_ORDER_TOTAL(p_order_id IN NUMBER) RETURN NUMBER;
    PROCEDURE CANCEL_ORDER(p_order_id IN NUMBER);
END PKG_ORDER_MGMT;
/

CREATE OR REPLACE PACKAGE BODY PKG_ORDER_MGMT AS

    -- internal helper with autonomous transaction (Oracle-specific pragma)
    PROCEDURE LOG_ACTION(p_table IN VARCHAR2, p_action IN VARCHAR2, p_details IN VARCHAR2) IS
        PRAGMA AUTONOMOUS_TRANSACTION;
    BEGIN
        INSERT INTO AUDIT_LOG (AUDIT_ID, TABLE_NAME, ACTION, ACTION_TS, DETAILS)
        VALUES (SEQ_AUDIT_ID.NEXTVAL, p_table, p_action, SYSTIMESTAMP, p_details);
        COMMIT;
    END LOG_ACTION;

    FUNCTION CALC_ORDER_TOTAL(p_order_id IN NUMBER) RETURN NUMBER IS
        v_total NUMBER(14,2);
    BEGIN
        SELECT NVL(SUM(QUANTITY * UNIT_PRICE), 0)
          INTO v_total
          FROM ORDER_ITEMS
         WHERE ORDER_ID = p_order_id;
        RETURN v_total;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RETURN 0;
    END CALC_ORDER_TOTAL;

    PROCEDURE SHIP_ORDER(p_order_id IN NUMBER, p_result OUT VARCHAR2) IS
        v_status   ORDERS.STATUS%TYPE;
        v_total    NUMBER;
        CURSOR c_items IS
            SELECT PRODUCT_ID, QUANTITY FROM ORDER_ITEMS WHERE ORDER_ID = p_order_id;
    BEGIN
        SELECT STATUS INTO v_status FROM ORDERS WHERE ORDER_ID = p_order_id FOR UPDATE;

        IF v_status <> 'NEW' THEN
            p_result := 'ERROR: order not in NEW status';
            RETURN;
        END IF;

        FOR rec IN c_items LOOP
            UPDATE PRODUCTS
               SET STOCK_QTY = STOCK_QTY - rec.QUANTITY
             WHERE PRODUCT_ID = rec.PRODUCT_ID;
            IF SQL%ROWCOUNT = 0 THEN
                RAISE_APPLICATION_ERROR(-20001, 'Missing product ' || rec.PRODUCT_ID);
            END IF;
        END LOOP;

        v_total := CALC_ORDER_TOTAL(p_order_id);
        UPDATE ORDERS SET STATUS = 'SHP', TOTAL_AMOUNT = v_total WHERE ORDER_ID = p_order_id;

        LOG_ACTION('ORDERS', 'SHIP', 'Order ' || p_order_id || ' shipped, total=' || TO_CHAR(v_total));
        p_result := 'OK';
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            p_result := 'ERROR: order not found';
        WHEN OTHERS THEN
            ROLLBACK;
            p_result := 'ERROR: ' || SQLERRM;
    END SHIP_ORDER;

    PROCEDURE CANCEL_ORDER(p_order_id IN NUMBER) IS
        TYPE t_id_tab IS TABLE OF ORDER_ITEMS.PRODUCT_ID%TYPE INDEX BY PLS_INTEGER;
        v_ids t_id_tab;
    BEGIN
        UPDATE ORDERS SET STATUS = 'CAN' WHERE ORDER_ID = p_order_id
        RETURNING ORDER_ID BULK COLLECT INTO v_ids;

        FORALL i IN 1 .. v_ids.COUNT
            UPDATE PRODUCTS SET STOCK_QTY = STOCK_QTY + 1 WHERE PRODUCT_ID = v_ids(i);

        LOG_ACTION('ORDERS', 'CANCEL', 'Order ' || p_order_id);
    END CANCEL_ORDER;

END PKG_ORDER_MGMT;
/
