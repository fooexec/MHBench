package org.openwes.wes.stock.controller;

import org.openwes.wes.api.stock.dto.ContainerStockDTO;
import org.openwes.common.utils.http.Response;
import org.openwes.wes.api.stock.IStockApi;
import org.openwes.wes.stock.controller.parameter.FreezeStockVO;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Validated
@RestController
@RequestMapping("stock/container/stock")
@RequiredArgsConstructor
@Tag(name = "Wms Module Api")
public class ContainerStockController {

    private final IStockApi iStockApi;

    @PostMapping("freezeContainerStock")
    public Object freezeContainerStock(
            @RequestBody @Valid FreezeStockVO freezeStockVO,
            @RequestHeader(value = "X-WarehouseID", required = false) String warehouseCode
    ) {
        requireStockWarehouse(freezeStockVO.getId(), warehouseCode);
        iStockApi.freezeContainerStock(freezeStockVO.getId(), freezeStockVO.getQty());
        return Response.success();
    }

    @PostMapping("unfreezeContainerStock")
    public Object unfreezeContainerStock(
            @RequestBody @Valid FreezeStockVO freezeStockVO,
            @RequestHeader(value = "X-WarehouseID", required = false) String warehouseCode
    ) {
        requireStockWarehouse(freezeStockVO.getId(), warehouseCode);
        iStockApi.unfreezeContainerStock(freezeStockVO.getId(), freezeStockVO.getQty());
        return Response.success();
    }

    private void requireStockWarehouse(Long stockId, String requestedWarehouseCode) {
        List<ContainerStockDTO> stocks = iStockApi.getContainerStocks(List.of(stockId));
        if (requestedWarehouseCode == null
                || requestedWarehouseCode.isBlank()
                || stocks.size() != 1
                || !requestedWarehouseCode.equals(stocks.get(0).getWarehouseCode())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "warehouse scope mismatch");
        }
    }
}
