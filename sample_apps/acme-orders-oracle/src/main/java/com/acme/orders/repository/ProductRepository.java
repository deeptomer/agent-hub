package com.acme.orders.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.acme.orders.model.Product;

/**
 * Spring Data JPA repository that falls back to Oracle native SQL for several queries.
 */
public interface ProductRepository extends JpaRepository<Product, Long> {

    // Oracle: NVL and ROWNUM inside a native query
    @Query(value =
        "SELECT * FROM PRODUCTS WHERE NVL(STOCK_QTY, 0) < :threshold AND ROWNUM <= :maxRows " +
        "ORDER BY STOCK_QTY",
        nativeQuery = true)
    List<Product> findLowStock(@Param("threshold") int threshold, @Param("maxRows") int maxRows);

    // Oracle: DECODE and string aggregation
    @Query(value =
        "SELECT CATEGORY, " +
        "       DECODE(SIGN(AVG(UNIT_PRICE) - 100), 1, 'PREMIUM', 0, 'MID', 'VALUE') AS PRICE_BAND, " +
        "       COUNT(*) AS PRODUCT_COUNT " +
        "FROM PRODUCTS GROUP BY CATEGORY",
        nativeQuery = true)
    List<Object[]> categoryPriceBands();

    // Oracle: MERGE-style stock adjustment inside a native modifying query
    @Modifying
    @Query(value =
        "UPDATE PRODUCTS SET STOCK_QTY = NVL(STOCK_QTY, 0) + :delta, " +
        "UNIT_PRICE = ROUND(UNIT_PRICE * :factor, 2) WHERE PRODUCT_ID = :id",
        nativeQuery = true)
    int adjustStockAndPrice(@Param("id") long id, @Param("delta") int delta, @Param("factor") double factor);

    // Oracle: case-insensitive search using UPPER and INSTR
    @Query(value =
        "SELECT * FROM PRODUCTS WHERE INSTR(UPPER(PRODUCT_NAME), UPPER(:term)) > 0",
        nativeQuery = true)
    List<Product> searchByName(@Param("term") String term);

    // Plain JPQL: portable, no migration work needed
    @Query("SELECT p FROM Product p WHERE p.category = :category ORDER BY p.productName")
    List<Product> findByCategorySorted(@Param("category") String category);
}
