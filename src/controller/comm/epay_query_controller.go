package comm

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/GMWalletApp/epusdt/middleware"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/GMWalletApp/epusdt/model/mdb"
	"github.com/GMWalletApp/epusdt/util/sign"
	"github.com/labstack/echo/v4"
)

const (
	epayQueryActionOrder = "order"
	epayTradeSuccess     = "TRADE_SUCCESS"
	epayTradeWaiting     = "WAITING"
)

var epayQueryAllowedParams = map[string]bool{
	"act":          true,
	"pid":          true,
	"key":          true,
	"out_trade_no": true,
}

// QueryEPayOrder exposes a read-only EasyPay-compatible order query endpoint.
// A successful response is signed so merchants can bind the queried order,
// amount, transaction ID, payment type, and chain transaction hash together.
func (c *BaseCommController) QueryEPayOrder(ctx echo.Context) error {
	values, err := ctx.FormParams()
	if err != nil {
		return epayQueryFailure(ctx, "invalid request")
	}
	params, ok := uniqueEPayQueryParams(values)
	if !ok || params["act"] != epayQueryActionOrder {
		return epayQueryFailure(ctx, "invalid request")
	}

	apiKeyRow, err := data.GetEnabledApiKey(params["pid"])
	if err != nil || apiKeyRow == nil || apiKeyRow.ID == 0 ||
		subtle.ConstantTimeCompare([]byte(apiKeyRow.SecretKey), []byte(params["key"])) != 1 ||
		!middleware.IsIPWhitelisted(apiKeyRow.IpWhitelist, ctx.RealIP()) {
		return epayQueryFailure(ctx, "authentication failed")
	}

	order, err := data.GetOrderInfoByOrderId(params["out_trade_no"])
	if err != nil || order == nil || order.ID == 0 || order.ApiKeyID != apiKeyRow.ID ||
		!strings.EqualFold(order.PaymentType, mdb.PaymentTypeEpay) {
		return epayQueryFailure(ctx, "order not found")
	}
	_ = data.TouchApiKeyUsage(apiKeyRow.ID)

	status := 0
	tradeStatus := epayTradeWaiting
	blockTransactionID := ""
	if order.Status == mdb.StatusPaySuccess {
		status = 1
		tradeStatus = epayTradeSuccess
		blockTransactionID = strings.TrimSpace(order.BlockTransactionId)
	}

	response := map[string]interface{}{
		"code":                 1,
		"msg":                  "success",
		"pid":                  apiKeyRow.Pid,
		"out_trade_no":         order.OrderId,
		"trade_no":             order.TradeId,
		"type":                 queryEPayResultType(order),
		"money":                fmt.Sprintf("%.4f", order.Amount),
		"trade_status":         tradeStatus,
		"status":               status,
		"block_transaction_id": blockTransactionID,
	}
	signature, err := sign.Get(response, apiKeyRow.SecretKey)
	if err != nil {
		return epayQueryFailure(ctx, "query failed")
	}
	response["sign"] = signature
	response["sign_type"] = "MD5"
	return ctx.JSON(http.StatusOK, response)
}

func queryEPayResultType(order *mdb.Orders) string {
	if order != nil {
		if paymentType := strings.TrimSpace(order.EpayType); paymentType != "" {
			return paymentType
		}
	}
	return "alipay"
}

func uniqueEPayQueryParams(values url.Values) (map[string]string, bool) {
	params := make(map[string]string, len(values))
	for key, items := range values {
		if !epayQueryAllowedParams[key] || len(items) != 1 {
			return nil, false
		}
		value := strings.TrimSpace(items[0])
		if value == "" {
			return nil, false
		}
		params[key] = value
	}
	for _, key := range []string{"act", "pid", "key", "out_trade_no"} {
		if params[key] == "" {
			return nil, false
		}
	}
	return params, true
}

func epayQueryFailure(ctx echo.Context, message string) error {
	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"code":   0,
		"msg":    strings.TrimSpace(message),
		"status": 0,
	})
}
